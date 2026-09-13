use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use steamguard::{
    AccountLinkError, AccountLinker, DeviceDetails, ExposeSecret, LoginApprover, SteamGuardAccount,
    UserLogin,
    accountlinker::{AccountLinkConfirmType, FinalizeLinkError},
    approver::Challenge,
    protobufs::{
        enums::ESessionPersistence,
        steammessages_auth_steamclient::{EAuthSessionGuardType, EAuthTokenPlatformType},
    },
    refresher::TokenRefresher,
    steamapi::AuthenticationClient,
    transport::WebApiTransport,
};

use crate::Account;
use crate::steam_trade::{TradeDetails, community_client, read_mobile_response, response_params};

pub(crate) enum SteamRequest {
    BeginEnrollment {
        username: String,
        password: String,
        existing: Option<(usize, SteamGuardAccount)>,
    },
    SubmitGuardCode(String),
    BeginTransfer,
    SubmitTransferCode(String),
    FinalizeEnrollment(String),
    LoadConfirmations(Vec<(usize, SteamGuardAccount)>),
    RespondConfirmation {
        account: SteamGuardAccount,
        id: String,
        nonce: String,
        accept: bool,
    },
    RespondConfirmations {
        groups: Vec<ConfirmationGroup>,
        accept: bool,
    },
    LoadLoginRequests(Vec<(usize, SteamGuardAccount)>),
    RespondLogin {
        account: SteamGuardAccount,
        client_id: u64,
        version: u16,
        accept: bool,
    },
}

#[derive(Clone)]
pub(crate) struct ConfirmationRow {
    pub account_index: usize,
    pub id: String,
    pub nonce: String,
    pub kind: String,
    pub headline: String,
    pub summary: String,
    pub created: u64,
    pub icon: Option<String>,
    pub is_trade: bool,
    pub is_market_sale: bool,
    pub load_id: u64,
    pub trade: Option<Result<TradeDetails, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConfirmationTarget {
    pub load_id: u64,
    pub id: String,
    pub nonce: String,
}

pub(crate) struct ConfirmationGroup {
    pub account: SteamGuardAccount,
    pub targets: Vec<ConfirmationTarget>,
}

#[derive(Clone)]
pub(crate) struct LoginRequestRow {
    pub account_index: usize,
    pub client_id: u64,
    pub version: u16,
    pub device: String,
    pub ip: String,
    pub location: String,
    pub warning: bool,
}

pub(crate) enum SteamEvent {
    Working(String),
    NeedGuardCode {
        device_code: bool,
        message: String,
    },
    NeedExternalApproval(String),
    NeedEnrollmentCode {
        destination: String,
        recovery_code: String,
        draft_account: Box<Account>,
    },
    AuthenticatorAlreadyPresent,
    NeedTransferCode,
    EnrollmentComplete {
        replace_index: Option<usize>,
        account: Box<Account>,
        recovery_code: String,
    },
    ConfirmationsLoaded(Vec<ConfirmationRow>),
    TradeDetailsLoaded {
        load_id: u64,
        id: String,
        details: Result<TradeDetails, String>,
    },
    LoginRequestsLoaded(Vec<LoginRequestRow>),
    ActionComplete(String),
    ConfirmationsBatchComplete {
        completed: Vec<ConfirmationTarget>,
        errors: Vec<String>,
    },
    Error(String),
}

enum PendingEnrollment {
    Login {
        login: UserLogin<WebApiTransport>,
        guard_type: EAuthSessionGuardType,
        existing: Option<(usize, SteamGuardAccount)>,
    },
    Link {
        linker: AccountLinker<WebApiTransport>,
        account: SteamGuardAccount,
        server_time: u64,
    },
    ExistingAuthenticator(AccountLinker<WebApiTransport>),
    Transfer(AccountLinker<WebApiTransport>),
}

pub(crate) fn start_worker() -> (Sender<SteamRequest>, Receiver<SteamEvent>) {
    let (request_tx, request_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    std::thread::spawn(move || worker_loop(request_rx, event_tx));
    (request_tx, event_rx)
}

fn transport() -> Result<WebApiTransport, String> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(45))
        .user_agent("MortySteamAuth/0.3")
        .build()
        .map_err(|error| format!("Не удалось создать сетевой клиент: {error}"))?;
    Ok(WebApiTransport::new(client))
}

fn worker_loop(request_rx: Receiver<SteamRequest>, event_tx: Sender<SteamEvent>) {
    let mut pending: Option<PendingEnrollment> = None;
    let detail_generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    while let Ok(request) = request_rx.recv() {
        match request {
            SteamRequest::BeginEnrollment {
                username,
                mut password,
                existing,
            } => {
                let result =
                    begin_enrollment(&event_tx, username, &password, existing, &mut pending);
                zeroize::Zeroize::zeroize(&mut password);
                if let Err(error) = result {
                    pending = None;
                    let _ = event_tx.send(SteamEvent::Error(error));
                }
            }
            SteamRequest::SubmitGuardCode(code) => {
                if let Err(error) = submit_guard(&event_tx, code, &mut pending) {
                    let _ = event_tx.send(SteamEvent::Error(error));
                }
            }
            SteamRequest::BeginTransfer => {
                let state = pending.take();
                match state {
                    Some(PendingEnrollment::ExistingAuthenticator(mut linker)) => {
                        let _ = event_tx.send(SteamEvent::Working(
                            "Запрашиваем SMS для переноса аутентификатора…".to_owned(),
                        ));
                        match linker.transfer_start() {
                            Ok(()) => {
                                pending = Some(PendingEnrollment::Transfer(linker));
                                let _ = event_tx.send(SteamEvent::NeedTransferCode);
                            }
                            Err(error) => {
                                let _ = event_tx.send(SteamEvent::Error(format!(
                                    "Не удалось начать перенос: {error}"
                                )));
                            }
                        }
                    }
                    other => {
                        pending = other;
                        let _ = event_tx.send(SteamEvent::Error(
                            "Нет активного переноса аутентификатора".to_owned(),
                        ));
                    }
                }
            }
            SteamRequest::SubmitTransferCode(code) => {
                let state = pending.take();
                match state {
                    Some(PendingEnrollment::Transfer(mut linker)) => {
                        let _ = event_tx.send(SteamEvent::Working(
                            "Завершаем перенос аутентификатора…".to_owned(),
                        ));
                        match linker.transfer_finish(code.trim()) {
                            Ok(account) => {
                                let recovery_code = account.revocation_code.expose_secret().clone();
                                let _ = event_tx.send(SteamEvent::EnrollmentComplete {
                                    replace_index: None,
                                    account: Box::new(account_from_steam(account)),
                                    recovery_code,
                                });
                            }
                            Err(error) => {
                                pending = Some(PendingEnrollment::Transfer(linker));
                                let _ = event_tx.send(SteamEvent::Error(format!(
                                    "Не удалось завершить перенос: {error}"
                                )));
                            }
                        }
                    }
                    other => {
                        pending = other;
                        let _ = event_tx.send(SteamEvent::Error(
                            "Сначала начните перенос аутентификатора".to_owned(),
                        ));
                    }
                }
            }
            SteamRequest::FinalizeEnrollment(code) => {
                if let Err(error) = finalize_enrollment(&event_tx, code, &mut pending) {
                    let _ = event_tx.send(SteamEvent::Error(error));
                }
            }
            SteamRequest::LoadConfirmations(accounts) => {
                let load_id =
                    detail_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let result = load_confirmations(accounts, load_id);
                if let Ok((rows, jobs)) = result {
                    let _ = event_tx.send(SteamEvent::ConfirmationsLoaded(rows));
                    let events = event_tx.clone();
                    let generation = detail_generation.clone();
                    thread::spawn(move || {
                        let mut games = std::collections::HashMap::new();
                        for (account, confirmation) in jobs {
                            if generation.load(std::sync::atomic::Ordering::Relaxed) != load_id {
                                break;
                            }
                            let details = crate::steam_trade::load_trade_details(
                                &account,
                                &confirmation,
                                &mut games,
                            );
                            if generation.load(std::sync::atomic::Ordering::Relaxed) != load_id {
                                break;
                            }
                            let _ = events.send(SteamEvent::TradeDetailsLoaded {
                                load_id,
                                id: confirmation.id,
                                details,
                            });
                        }
                    });
                } else if let Err(error) = result {
                    let _ = event_tx.send(SteamEvent::Error(error));
                }
            }
            SteamRequest::RespondConfirmation {
                account,
                id,
                nonce,
                accept,
            } => {
                let result = respond_confirmation(account, &id, &nonce, accept);
                let _ = event_tx.send(match result {
                    Ok(()) => SteamEvent::ActionComplete(if accept {
                        "Подтверждение принято".to_owned()
                    } else {
                        "Подтверждение отклонено".to_owned()
                    }),
                    Err(error) => SteamEvent::Error(error),
                });
            }
            SteamRequest::RespondConfirmations { groups, accept } => {
                let mut completed = Vec::new();
                let mut errors = Vec::new();
                for group in groups {
                    let name = group.account.account_name.clone();
                    match respond_confirmations(group.account, &group.targets, accept) {
                        Ok(()) => completed.extend(group.targets),
                        Err(error) => errors.push(format!("{name}: {error}")),
                    }
                }
                let _ = event_tx.send(SteamEvent::ConfirmationsBatchComplete { completed, errors });
            }
            SteamRequest::LoadLoginRequests(accounts) => {
                let result = load_login_requests(accounts);
                let _ = event_tx.send(match result {
                    Ok(rows) => SteamEvent::LoginRequestsLoaded(rows),
                    Err(error) => SteamEvent::Error(error),
                });
            }
            SteamRequest::RespondLogin {
                account,
                client_id,
                version,
                accept,
            } => {
                let result = respond_login(account, client_id, version, accept);
                let _ = event_tx.send(match result {
                    Ok(()) => SteamEvent::ActionComplete(if accept {
                        "Вход подтверждён".to_owned()
                    } else {
                        "Вход отклонён".to_owned()
                    }),
                    Err(error) => SteamEvent::Error(error),
                });
            }
        }
    }
}

fn begin_enrollment(
    event_tx: &Sender<SteamEvent>,
    username: String,
    password: &str,
    existing: Option<(usize, SteamGuardAccount)>,
    pending: &mut Option<PendingEnrollment>,
) -> Result<(), String> {
    event_tx
        .send(SteamEvent::Working("Входим в Steam…".to_owned()))
        .ok();
    let transport = transport()?;
    let time_transport = transport.clone();
    let details = DeviceDetails {
        friendly_name: "Morty Steam Auth for Windows".to_owned(),
        platform_type: EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp,
        os_type: 16,
        gaming_device_type: 1,
    };
    let mut login = UserLogin::new(transport, details);
    let methods = login
        .begin_auth_via_credentials(&username, password)
        .map_err(|error| login_error(&error))?;

    let device = EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode;
    let email = EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode;
    let external_device = EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation;
    let external_email = EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation;

    if let Some(method) = methods
        .iter()
        .find(|method| method.confirmation_type == device)
    {
        if let Some((_, account)) = existing.as_ref() {
            event_tx
                .send(SteamEvent::Working(
                    "Автоматически подставляем текущий Steam Guard-код…".to_owned(),
                ))
                .ok();
            let now = steamguard::steamapi::get_server_time(time_transport)
                .map(|response| response.server_time())
                .unwrap_or_else(|_| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                });
            let code = account.generate_code(now);
            match login.submit_steam_guard_code(device, code) {
                Ok(_) => {
                    let tokens = login
                        .poll_until_tokens()
                        .map_err(|error| format!("Не удалось получить сессию Steam: {error}"))?;
                    return after_login(event_tx, login, tokens, existing, pending);
                }
                Err(error) => {
                    *pending = Some(PendingEnrollment::Login {
                        login,
                        guard_type: device,
                        existing,
                    });
                    event_tx
                        .send(SteamEvent::NeedGuardCode {
                            device_code: true,
                            message: format!(
                                "Steam отклонил автоматически созданный код ({error}). Проверьте системное время Windows и при необходимости введите код вручную"
                            ),
                        })
                        .ok();
                    return Ok(());
                }
            }
        }
        let message = if method.associated_messsage.is_empty() {
            "Введите код из текущего Steam Guard".to_owned()
        } else {
            method.associated_messsage.clone()
        };
        *pending = Some(PendingEnrollment::Login {
            login,
            guard_type: device,
            existing,
        });
        event_tx
            .send(SteamEvent::NeedGuardCode {
                device_code: true,
                message,
            })
            .ok();
        return Ok(());
    }
    if let Some(method) = methods
        .iter()
        .find(|method| method.confirmation_type == email)
    {
        let message = if method.associated_messsage.is_empty() {
            "Введите код из письма Steam".to_owned()
        } else {
            method.associated_messsage.clone()
        };
        *pending = Some(PendingEnrollment::Login {
            login,
            guard_type: email,
            existing,
        });
        event_tx
            .send(SteamEvent::NeedGuardCode {
                device_code: false,
                message,
            })
            .ok();
        return Ok(());
    }

    if methods.iter().any(|method| {
        method.confirmation_type == external_device || method.confirmation_type == external_email
    }) {
        event_tx
            .send(SteamEvent::NeedExternalApproval(
                "Подтвердите вход в текущем приложении Steam или по ссылке в письме".to_owned(),
            ))
            .ok();
    }
    let tokens = login
        .poll_until_tokens()
        .map_err(|error| format!("Не удалось получить сессию Steam: {error}"))?;
    after_login(event_tx, login, tokens, existing, pending)
}

fn submit_guard(
    event_tx: &Sender<SteamEvent>,
    code: String,
    pending: &mut Option<PendingEnrollment>,
) -> Result<(), String> {
    let state = pending.take();
    let Some(PendingEnrollment::Login {
        mut login,
        guard_type,
        existing,
    }) = state
    else {
        *pending = state;
        return Err("Нет активной авторизации Steam".to_owned());
    };
    event_tx
        .send(SteamEvent::Working(
            "Проверяем код и получаем сессию…".to_owned(),
        ))
        .ok();
    if let Err(error) = login.submit_steam_guard_code(guard_type, code.trim().to_owned()) {
        *pending = Some(PendingEnrollment::Login {
            login,
            guard_type,
            existing,
        });
        return Err(format!("Steam отклонил код: {error}"));
    }
    let tokens = login
        .poll_until_tokens()
        .map_err(|error| format!("Не удалось получить сессию Steam: {error}"))?;
    after_login(event_tx, login, tokens, existing, pending)
}

fn after_login(
    event_tx: &Sender<SteamEvent>,
    login: UserLogin<WebApiTransport>,
    tokens: steamguard::token::Tokens,
    existing: Option<(usize, SteamGuardAccount)>,
    pending: &mut Option<PendingEnrollment>,
) -> Result<(), String> {
    drop(login);
    if let Some((index, mut account)) = existing {
        account.set_tokens(tokens);
        event_tx
            .send(SteamEvent::EnrollmentComplete {
                replace_index: Some(index),
                account: Box::new(account_from_steam(account)),
                recovery_code: String::new(),
            })
            .ok();
        return Ok(());
    }

    event_tx
        .send(SteamEvent::Working(
            "Подключаем мобильный аутентификатор…".to_owned(),
        ))
        .ok();
    let mut linker = AccountLinker::new(transport()?, tokens);
    match linker.link() {
        Ok(link) => {
            let destination = match link.confirm_type() {
                AccountLinkConfirmType::SMS => format!(
                    "Введите код из SMS (номер оканчивается на {})",
                    link.phone_number_hint()
                ),
                AccountLinkConfirmType::Email => "Введите код из письма Steam".to_owned(),
                AccountLinkConfirmType::Unknown(value) => {
                    return Err(format!(
                        "Steam запросил неизвестный тип подтверждения: {value}"
                    ));
                }
            };
            let server_time = link.server_time();
            let account = link.into_account();
            let recovery_code = account.revocation_code.expose_secret().clone();
            let draft_account = Box::new(account_from_steam(account.clone()));
            *pending = Some(PendingEnrollment::Link {
                linker,
                account,
                server_time,
            });
            event_tx
                .send(SteamEvent::NeedEnrollmentCode {
                    destination,
                    recovery_code,
                    draft_account,
                })
                .ok();
            Ok(())
        }
        Err(AccountLinkError::AuthenticatorPresent) => {
            *pending = Some(PendingEnrollment::ExistingAuthenticator(linker));
            event_tx.send(SteamEvent::AuthenticatorAlreadyPresent).ok();
            Ok(())
        }
        Err(error) => Err(format!("Не удалось подключить аутентификатор: {error}")),
    }
}

fn finalize_enrollment(
    event_tx: &Sender<SteamEvent>,
    code: String,
    pending: &mut Option<PendingEnrollment>,
) -> Result<(), String> {
    let Some(PendingEnrollment::Link {
        linker,
        account,
        server_time,
    }) = pending.as_mut()
    else {
        return Err("Нет незавершённого подключения аутентификатора".to_owned());
    };
    event_tx
        .send(SteamEvent::Working(
            "Завершаем подключение аутентификатора…".to_owned(),
        ))
        .ok();
    let mut tries = 0;
    loop {
        match linker.finalize(*server_time, account, code.trim().to_owned()) {
            Ok(()) => break,
            Err(FinalizeLinkError::WantMore { server_time: time }) if tries < 30 => {
                *server_time = time;
                tries += 1;
            }
            Err(error) => return Err(format!("Steam не завершил подключение: {error}")),
        }
    }
    let status = linker
        .query_status(account)
        .map_err(|error| format!("Не удалось проверить аутентификатор: {error}"))?;
    if status.state() == 0 {
        return Err("Steam не активировал аутентификатор; проверьте код и повторите".to_owned());
    }
    let recovery_code = account.revocation_code.expose_secret().clone();
    let finished = account_from_steam(account.clone());
    *pending = None;
    event_tx
        .send(SteamEvent::EnrollmentComplete {
            replace_index: None,
            account: Box::new(finished),
            recovery_code,
        })
        .ok();
    Ok(())
}

fn load_confirmations(
    accounts: Vec<(usize, SteamGuardAccount)>,
    load_id: u64,
) -> Result<
    (
        Vec<ConfirmationRow>,
        Vec<(SteamGuardAccount, steamguard::Confirmation)>,
    ),
    String,
> {
    let transport = transport()?;
    let mut rows = Vec::new();
    let mut jobs = Vec::new();
    for (account_index, mut account) in accounts {
        if account.tokens.is_none() || account.identity_secret.expose_secret().is_empty() {
            continue;
        }
        refresh_access_token(&mut account, &transport)?;
        let confirmations = get_confirmations_with_retry(&transport, &account)
            .map_err(|error| format!("{}: {error}", account.account_name))?;
        for confirmation in confirmations {
            let is_trade = confirmation.conf_type == steamguard::ConfirmationType::Trade;
            let is_market_sale = confirmation.conf_type == steamguard::ConfirmationType::MarketSell;
            if is_trade {
                jobs.push((account.clone(), confirmation.clone()));
            }
            rows.push(ConfirmationRow {
                account_index,
                id: confirmation.id,
                nonce: confirmation.nonce,
                kind: confirmation.type_name,
                headline: confirmation.headline,
                summary: confirmation.summary.join(" · "),
                created: confirmation.creation_time,
                icon: confirmation.icon,
                is_trade,
                is_market_sale,
                load_id,
                trade: None,
            });
        }
    }
    Ok((rows, jobs))
}

fn get_confirmations_with_retry(
    transport: &WebApiTransport,
    account: &SteamGuardAccount,
) -> Result<Vec<steamguard::Confirmation>, String> {
    const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(400), Duration::from_millis(900)];
    let client = community_client(account)?;
    let time = steamguard::steamapi::get_server_time(transport.clone())
        .map_err(|error| {
            format!(
                "Не удалось получить время Steam: {}",
                error_chain(error.as_ref())
            )
        })?
        .server_time();
    let started = std::time::Instant::now();
    for attempt in 0..=RETRY_DELAYS.len() {
        match crate::steam_trade::get_confirmations(
            &client,
            account,
            time + started.elapsed().as_secs(),
        ) {
            Ok(confirmations) => return Ok(confirmations),
            Err(error) if error.retryable && attempt < RETRY_DELAYS.len() => {
                thread::sleep(RETRY_DELAYS[attempt])
            }
            Err(error) => return Err(error.message),
        }
    }
    unreachable!("final attempt always returns")
}

fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let detail = cause.to_string();
        if !message.contains(&detail) {
            message.push_str(": ");
            message.push_str(&detail);
        }
        source = cause.source();
    }
    message
}

fn respond_confirmation(
    mut account: SteamGuardAccount,
    id: &str,
    nonce: &str,
    accept: bool,
) -> Result<(), String> {
    let transport = transport()?;
    refresh_access_token(&mut account, &transport)?;
    let time = steamguard::steamapi::get_server_time(transport)
        .map_err(|error| {
            format!(
                "Не удалось получить время Steam: {}",
                error_chain(error.as_ref())
            )
        })?
        .server_time();
    let params = response_params(&account, time, id, nonce, accept)?;
    let response = community_client(&account)?
        .get("https://steamcommunity.com/mobileconf/ajaxop")
        .query(&params)
        .send()
        .map_err(|error| {
            format!(
                "Не удалось отправить ответ в Steam: {}",
                error.without_url()
            )
        })?;
    read_mobile_response(response).map(|_| ())
}

fn respond_confirmations(
    mut account: SteamGuardAccount,
    targets: &[ConfirmationTarget],
    accept: bool,
) -> Result<(), String> {
    if targets.is_empty() {
        return Ok(());
    }
    let transport = transport()?;
    refresh_access_token(&mut account, &transport)?;
    let time = steamguard::steamapi::get_server_time(transport)
        .map_err(|error| {
            format!(
                "Не удалось получить время Steam: {}",
                error_chain(error.as_ref())
            )
        })?
        .server_time();
    let params = crate::steam_trade::batch_response_params(&account, time, targets, accept)?;
    let response = community_client(&account)?
        .post("https://steamcommunity.com/mobileconf/multiajaxop")
        .form(&params)
        .send()
        .map_err(|error| {
            format!(
                "Не удалось отправить ответ в Steam: {}",
                error.without_url()
            )
        })?;
    read_mobile_response(response).map(|_| ())
}

fn load_login_requests(
    accounts: Vec<(usize, SteamGuardAccount)>,
) -> Result<Vec<LoginRequestRow>, String> {
    let transport = transport()?;
    let mut rows = Vec::new();
    for (account_index, mut account) in accounts {
        let Some(tokens) = account.tokens.as_ref() else {
            continue;
        };
        let _ = tokens;
        refresh_access_token(&mut account, &transport)?;
        let tokens = account.tokens.as_ref().expect("tokens checked above");
        let approver = LoginApprover::new(transport.clone(), tokens);
        let client_ids = approver
            .list_auth_sessions()
            .map_err(|error| format!("{}: {error}", account.account_name))?;
        for client_id in client_ids {
            let info = approver
                .get_auth_session_info(client_id)
                .map_err(|error| format!("{}: {error}", account.account_name))?;
            let location = [info.city(), info.state(), info.country()]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            rows.push(LoginRequestRow {
                account_index,
                client_id,
                version: info.version().max(1) as u16,
                device: if info.device_friendly_name().is_empty() {
                    format!("{:?}", info.platform_type())
                } else {
                    info.device_friendly_name().to_owned()
                },
                ip: info.ip().to_owned(),
                location,
                warning: info.requestor_location_mismatch() || info.high_usage_login(),
            });
        }
    }
    Ok(rows)
}

fn respond_login(
    mut account: SteamGuardAccount,
    client_id: u64,
    version: u16,
    accept: bool,
) -> Result<(), String> {
    let transport = transport()?;
    refresh_access_token(&mut account, &transport)?;
    let tokens = account
        .tokens
        .as_ref()
        .ok_or("Для аккаунта нет активной сессии Steam")?;
    let mut approver = LoginApprover::new(transport, tokens);
    let challenge = Challenge::new(version, client_id);
    let result = if accept {
        approver.approve(
            &account,
            challenge,
            ESessionPersistence::k_ESessionPersistence_Persistent,
        )
    } else {
        approver.deny(&account, challenge)
    };
    result.map_err(|error| format!("Не удалось ответить на запрос входа: {error}"))
}

fn refresh_access_token(
    account: &mut SteamGuardAccount,
    transport: &WebApiTransport,
) -> Result<(), String> {
    let Some(tokens) = account.tokens.clone() else {
        return Err(format!(
            "{}: требуется авторизация Steam",
            account.account_name
        ));
    };
    let mut refresher = TokenRefresher::new(AuthenticationClient::new(transport.clone()));
    let access_token = refresher
        .refresh(account.steam_id, &tokens)
        .map_err(|error| format!("{}: сессия Steam истекла ({error})", account.account_name))?;
    let mut refreshed = tokens;
    refreshed.set_access_token(access_token);
    account.set_tokens(refreshed);
    Ok(())
}

fn account_from_steam(account: SteamGuardAccount) -> Account {
    Account {
        name: account.account_name.clone(),
        steam_id: Some(account.steam_id.to_string()),
        shared_secret: BASE64.encode(account.shared_secret.expose_secret()),
        mobile: Some(account),
    }
}

fn login_error(error: &steamguard::LoginError) -> String {
    match error {
        steamguard::LoginError::BadCredentials => "Неверный логин или пароль Steam".to_owned(),
        steamguard::LoginError::TooManyAttempts => {
            "Steam временно ограничил попытки входа. Попробуйте позже".to_owned()
        }
        steamguard::LoginError::SessionExpired => "Сессия входа Steam истекла".to_owned(),
        _ => format!("Не удалось войти в Steam: {error}"),
    }
}
