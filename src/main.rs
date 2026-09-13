#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod steam;
mod steam_trade;

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use directories::ProjectDirs;
use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke, Vec2};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use walkdir::WalkDir;
use zeroize::Zeroize;

use steam::{ConfirmationGroup, ConfirmationTarget};
use steam::{ConfirmationRow, LoginRequestRow, SteamEvent, SteamRequest};

#[derive(Clone, Copy)]
enum ConfirmationScope {
    All,
    Trades,
    Sales,
}

impl ConfirmationScope {
    fn matches(self, row: &ConfirmationRow) -> bool {
        match self {
            Self::All => true,
            Self::Trades => row.is_trade,
            Self::Sales => row.is_market_sale,
        }
    }
}

const APP_NAME: &str = "Morty Steam Auth";
const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
const LOGO_BYTES: &[u8] = include_bytes!("../logo.png");
const TRAY_POPUP_WIDTH: f32 = 310.0;
const TRAY_ACCOUNT_HEIGHT: f32 = 48.0;
const TRAY_POPUP_TITLE: &str = "Morty Steam Auth — быстрые коды";

#[derive(Clone, Serialize, Deserialize)]
struct Account {
    name: String,
    steam_id: Option<String>,
    shared_secret: String,
    #[serde(default)]
    mobile: Option<steamguard::SteamGuardAccount>,
}

#[derive(Default, Serialize, Deserialize)]
struct VaultData {
    accounts: Vec<Account>,
}

#[derive(Serialize, Deserialize)]
struct VaultEnvelope {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Setup,
    Locked,
    Ready,
}

#[derive(Clone, Copy, PartialEq)]
enum ReadyTab {
    Codes,
    Confirmations,
    LoginRequests,
}

enum AddStage {
    Credentials,
    Working(String),
    GuardCode {
        message: String,
    },
    ExternalApproval(String),
    EnrollmentCode {
        destination: String,
        recovery_code: String,
    },
    ExistingAuthenticator,
    TransferCode,
    Complete {
        recovery_code: String,
    },
}

struct AddDialog {
    username: String,
    password: String,
    code: String,
    existing_index: Option<usize>,
    result_index: Option<usize>,
    stage: AddStage,
}

impl AddDialog {
    fn new(existing_index: Option<usize>, username: String) -> Self {
        Self {
            username,
            password: String::new(),
            code: String::new(),
            existing_index,
            result_index: None,
            stage: AddStage::Credentials,
        }
    }
}

struct Notice {
    text: String,
    error: bool,
    created: Instant,
}

struct TrayPopup {
    position: egui::Pos2,
    close_sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mouse_buttons: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

struct TrayCodeAccount {
    login: String,
    shared_secret: String,
}

impl Drop for TrayCodeAccount {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

#[derive(Clone, Copy)]
enum TrayAction {
    ClosePopup,
    RestoreWindow,
}

#[derive(Clone, Copy)]
enum TrayPointerAction {
    None,
    Close,
    Exit,
}

struct MortySteamAuthApp {
    screen: Screen,
    accounts: Vec<Account>,
    password: String,
    password_repeat: String,
    search: String,
    key: Option<[u8; 32]>,
    salt: Option<[u8; 16]>,
    vault_path: PathBuf,
    notice: Option<Notice>,
    pending_delete: Option<usize>,
    ready_tab: ReadyTab,
    add_dialog: Option<AddDialog>,
    confirmations: Vec<ConfirmationRow>,
    confirmation_account_filter: Option<usize>,
    login_requests: Vec<LoginRequestRow>,
    steam_busy: bool,
    steam_tx: std::sync::mpsc::Sender<SteamRequest>,
    steam_rx: std::sync::mpsc::Receiver<SteamEvent>,
    tray_icon: Option<tray_icon::TrayIcon>,
    tray_rx: std::sync::mpsc::Receiver<tray_icon::TrayIconEvent>,
    tray_action_tx: std::sync::mpsc::Sender<TrayAction>,
    tray_action_rx: std::sync::mpsc::Receiver<TrayAction>,
    tray_popup: Option<TrayPopup>,
    main_window_hidden: bool,
    exit_requested: bool,
    logo: egui::TextureHandle,
}

impl MortySteamAuthApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let logo = load_logo(&cc.egui_ctx);

        let vault_path = vault_path();
        let screen = if vault_path.exists() {
            Screen::Locked
        } else {
            Screen::Setup
        };
        let (steam_tx, steam_rx) = steam::start_worker();

        let (tray_tx, tray_rx) = std::sync::mpsc::channel();
        let repaint_context = cc.egui_ctx.clone();
        tray_icon::TrayIconEvent::set_event_handler(Some(move |event| {
            let should_wake_root = matches!(
                &event,
                tray_icon::TrayIconEvent::Click {
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                } | tray_icon::TrayIconEvent::DoubleClick { .. }
            );
            let _ = tray_tx.send(event);
            if should_wake_root {
                // A fully hidden window is not repainted by Windows. Briefly wake
                // the root viewport so it can dispatch the tray event; update()
                // hides it again in the same pass unless the user chose Restore.
                wake_main_window_native();
                repaint_context.send_viewport_cmd_to(
                    egui::ViewportId::ROOT,
                    egui::ViewportCommand::Visible(true),
                );
                repaint_context.request_repaint_of(egui::ViewportId::ROOT);
            }
        }));
        let tray_icon = create_tray_icon().ok();
        let (tray_action_tx, tray_action_rx) = std::sync::mpsc::channel();

        Self {
            screen,
            accounts: Vec::new(),
            password: String::new(),
            password_repeat: String::new(),
            search: String::new(),
            key: None,
            salt: None,
            vault_path,
            notice: None,
            pending_delete: None,
            ready_tab: ReadyTab::Codes,
            add_dialog: None,
            confirmations: Vec::new(),
            confirmation_account_filter: None,
            login_requests: Vec::new(),
            steam_busy: false,
            steam_tx,
            steam_rx,
            tray_icon,
            tray_rx,
            tray_action_tx,
            tray_action_rx,
            tray_popup: None,
            main_window_hidden: false,
            exit_requested: false,
            logo,
        }
    }

    fn process_tray_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.tray_rx.try_recv() {
            match event {
                tray_icon::TrayIconEvent::Click {
                    position,
                    button: tray_icon::MouseButton::Right,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                } => {
                    let scale = ctx.pixels_per_point().max(0.1) as f64;
                    let popup_height = tray_popup_height(self.screen, self.accounts.len());
                    self.tray_popup = Some(TrayPopup {
                        position: egui::pos2(
                            (position.x / scale) as f32 - TRAY_POPUP_WIDTH + 18.0,
                            (position.y / scale) as f32 - popup_height - 12.0,
                        ),
                        close_sent: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        mouse_buttons: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
                    });
                    ctx.request_repaint();
                }
                tray_icon::TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                }
                | tray_icon::TrayIconEvent::DoubleClick {
                    button: tray_icon::MouseButton::Left,
                    ..
                } => {
                    self.tray_popup = None;
                    self.main_window_hidden = false;
                    restore_main_window(ctx);
                }
                _ => {}
            }
        }
    }

    fn process_tray_actions(&mut self, ctx: &egui::Context) {
        while let Ok(action) = self.tray_action_rx.try_recv() {
            match action {
                TrayAction::ClosePopup => self.tray_popup = None,
                TrayAction::RestoreWindow => {
                    self.tray_popup = None;
                    self.main_window_hidden = false;
                    restore_main_window(ctx);
                }
            }
        }
    }

    fn tray_popup_ui(&mut self, ctx: &egui::Context) {
        let Some(popup) = &self.tray_popup else {
            return;
        };

        let position = popup.position;
        let close_sent = popup.close_sent.clone();
        let mouse_buttons = popup.mouse_buttons.clone();
        let popup_height = tray_popup_height(self.screen, self.accounts.len());
        let screen = self.screen;
        let accounts = if self.screen == Screen::Ready {
            self.accounts
                .iter()
                .map(|account| TrayCodeAccount {
                    login: account.name.clone(),
                    shared_secret: account.shared_secret.clone(),
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let action_tx = self.tray_action_tx.clone();

        ctx.show_viewport_deferred(
            egui::ViewportId::from_hash_of("tray_quick_codes"),
            egui::ViewportBuilder::default()
                .with_title(TRAY_POPUP_TITLE)
                .with_inner_size([TRAY_POPUP_WIDTH, popup_height])
                .with_position(position)
                .with_visible(true)
                .with_decorations(false)
                .with_resizable(false)
                .with_maximize_button(false)
                .with_minimize_button(false)
                .with_taskbar(false)
                .with_always_on_top()
                .with_active(true),
            move |popup_ctx, _viewport_class| {
                configure_style(popup_ctx);
                popup_ctx.request_repaint_after(Duration::from_millis(16));

                let send_action = |action| {
                    if matches!(action, TrayAction::ClosePopup)
                        && close_sent.swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        return;
                    }
                    let _ = action_tx.send(action);
                    popup_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    match action {
                        TrayAction::ClosePopup => {}
                        TrayAction::RestoreWindow => {
                            popup_ctx.send_viewport_cmd_to(
                                egui::ViewportId::ROOT,
                                egui::ViewportCommand::Visible(true),
                            );
                            popup_ctx.request_repaint_of(egui::ViewportId::ROOT);
                        }
                    }
                };

                let close_requested = popup_ctx.input(|input| {
                    input.viewport().close_requested() || input.key_pressed(egui::Key::Escape)
                });
                if close_requested {
                    send_action(TrayAction::ClosePopup);
                }
                match tray_pointer_action(&mouse_buttons) {
                    TrayPointerAction::None => {}
                    TrayPointerAction::Close => send_action(TrayAction::ClosePopup),
                    TrayPointerAction::Exit => std::process::exit(0),
                }

                egui::TopBottomPanel::bottom("tray_exit_footer")
                    .exact_height(62.0)
                    .frame(
                        egui::Frame::new()
                            .fill(sidebar())
                            .stroke(Stroke::new(1.0_f32, border()))
                            .inner_margin(egui::Margin::symmetric(14, 7)),
                    )
                    .show(popup_ctx, |ui| {
                        ui.set_width(ui.available_width());
                        if tray_exit_button(ui).clicked() {
                            std::process::exit(0);
                        }
                    });

                egui::CentralPanel::default()
                    .frame(
                        egui::Frame::new()
                            .fill(sidebar())
                            .stroke(Stroke::new(1.0_f32, border()))
                            .inner_margin(egui::Margin::same(14)),
                    )
                    .show(popup_ctx, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new("QUICK CODES")
                                        .size(10.0)
                                        .strong()
                                        .color(accent()),
                                );
                                ui.label(RichText::new(APP_NAME).size(16.0).strong());
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let status_color = if screen == Screen::Ready {
                                        success()
                                    } else {
                                        subtle()
                                    };
                                    let (status_rect, _) = ui.allocate_exact_size(
                                        Vec2::splat(12.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter()
                                        .circle_filled(status_rect.center(), 4.0, status_color);
                                },
                            );
                        });
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(6.0);

                        if screen != Screen::Ready {
                            egui::Frame::new()
                                .fill(elevated())
                                .corner_radius(CornerRadius::same(10))
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.label(
                                        RichText::new("Хранилище заблокировано")
                                            .size(13.0)
                                            .strong(),
                                    );
                                    ui.label(
                                        RichText::new("Откройте окно и введите пароль")
                                            .size(11.0)
                                            .color(muted()),
                                    );
                                });
                            ui.add_space(8.0);
                            if ui
                                .add_sized(
                                    [ui.available_width(), 40.0],
                                    primary_button("Открыть приложение"),
                                )
                                .clicked()
                            {
                                send_action(TrayAction::RestoreWindow);
                            }
                        } else if accounts.is_empty() {
                            ui.add_space(12.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new("Аккаунтов пока нет")
                                        .size(13.0)
                                        .color(muted()),
                                );
                                ui.label(
                                    RichText::new("Добавьте maFile в приложении")
                                        .size(11.0)
                                        .color(subtle()),
                                );
                            });
                            ui.add_space(12.0);
                        } else {
                            egui::ScrollArea::vertical()
                                .id_salt("tray_accounts")
                                .max_height(TRAY_ACCOUNT_HEIGHT * 6.0)
                                .auto_shrink([false, true])
                                .scroll_bar_visibility(
                                    egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden,
                                )
                                .show(ui, |ui| {
                                    let timestamp = unix_time_precise() as u64;
                                    for account in &accounts {
                                        let code = steam_guard_code(
                                            &account.shared_secret,
                                            timestamp,
                                        )
                                        .ok();
                                        let code_text = code.as_deref().unwrap_or("-----");
                                        let response =
                                            tray_account_row(ui, &account.login, code_text);
                                        if response.clicked() {
                                            if let Some(code) = &code {
                                                popup_ctx.copy_text(code.clone());
                                                send_action(TrayAction::ClosePopup);
                                            }
                                        }
                                        ui.add_space(4.0);
                                    }
                                });
                        }

                    });
            },
        );
    }

    fn show_notice(&mut self, text: impl Into<String>, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
            created: Instant::now(),
        });
    }

    fn create_vault(&mut self) {
        if self.password.len() < 8 {
            self.show_notice("Пароль должен содержать минимум 8 символов", true);
            return;
        }
        if self.password != self.password_repeat {
            self.show_notice("Пароли не совпадают", true);
            return;
        }

        let mut salt = [0_u8; 16];
        if let Err(error) = getrandom::fill(&mut salt) {
            self.show_notice(format!("Не удалось создать соль: {error}"), true);
            return;
        }

        match derive_key(&self.password, &salt) {
            Ok(key) => {
                self.key = Some(key);
                self.salt = Some(salt);
                self.password.zeroize();
                self.password_repeat.zeroize();
                self.screen = Screen::Ready;
                if let Err(error) = self.save_vault() {
                    self.show_notice(error, true);
                } else {
                    self.show_notice("Зашифрованное хранилище создано", false);
                }
            }
            Err(error) => self.show_notice(error, true),
        }
    }

    fn unlock(&mut self) {
        let result = load_vault(&self.vault_path, &self.password);
        self.password.zeroize();

        match result {
            Ok((data, key, salt)) => {
                self.accounts = data.accounts;
                self.key = Some(key);
                self.salt = Some(salt);
                self.screen = Screen::Ready;
                self.show_notice("Хранилище разблокировано", false);
            }
            Err(error) => self.show_notice(error, true),
        }
    }

    fn lock(&mut self) {
        for account in &mut self.accounts {
            account.shared_secret.zeroize();
        }
        self.accounts.clear();
        if let Some(mut key) = self.key.take() {
            key.zeroize();
        }
        self.salt = None;
        self.search.clear();
        self.confirmations.clear();
        self.confirmation_account_filter = None;
        self.login_requests.clear();
        self.add_dialog = None;
        self.screen = Screen::Locked;
        self.show_notice("Хранилище заблокировано", false);
    }

    fn save_vault(&self) -> Result<(), String> {
        let key = self.key.as_ref().ok_or("Хранилище заблокировано")?;
        let salt = self.salt.as_ref().ok_or("Нет соли хранилища")?;
        let data = VaultData {
            accounts: self.accounts.clone(),
        };
        save_vault(&self.vault_path, &data, key, salt)
    }

    fn import_paths(&mut self, paths: Vec<PathBuf>) {
        let mut imported = 0_usize;
        let mut upgraded = 0_usize;
        let mut skipped = 0_usize;
        let mut last_error = None;

        for path in paths {
            match parse_mafile(&path) {
                Ok(account) => {
                    if let Some(index) = self
                        .accounts
                        .iter()
                        .position(|current| current.shared_secret == account.shared_secret)
                    {
                        if self.accounts[index].mobile.is_none() && account.mobile.is_some() {
                            self.accounts[index] = account;
                            upgraded += 1;
                        } else {
                            skipped += 1;
                        }
                    } else {
                        self.accounts.push(account);
                        imported += 1;
                    }
                }
                Err(error) => {
                    skipped += 1;
                    last_error = Some(error);
                }
            }
        }

        if imported > 0 || upgraded > 0 {
            match self.save_vault() {
                Ok(()) => self.show_notice(
                    format!(
                        "Импортировано: {imported}, обновлено для подтверждений: {upgraded}, пропущено: {skipped}"
                    ),
                    false,
                ),
                Err(error) => self.show_notice(error, true),
            }
        } else if let Some(error) = last_error {
            self.show_notice(error, true);
        } else {
            self.show_notice("Новых аккаунтов не найдено", true);
        }
    }

    fn pick_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .set_title("Выберите maFile")
            .add_filter("Steam maFile", &["maFile", "json"])
            .pick_files()
        {
            self.import_paths(paths);
        }
    }

    fn pick_folder(&mut self) {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Выберите папку с maFiles")
            .pick_folder()
        {
            let paths = WalkDir::new(folder)
                .max_depth(4)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_file())
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| {
                            extension.eq_ignore_ascii_case("mafile")
                                || extension.eq_ignore_ascii_case("json")
                        })
                })
                .map(|entry| entry.into_path())
                .collect();
            self.import_paths(paths);
        }
    }

    fn open_steam_login(&mut self, existing_index: Option<usize>) {
        let username = existing_index
            .and_then(|index| self.accounts.get(index))
            .map(|account| account.name.clone())
            .unwrap_or_default();
        self.add_dialog = Some(AddDialog::new(existing_index, username));
    }

    fn open_account_confirmations(&mut self, index: usize) {
        let Some(account) = self.accounts.get(index) else {
            return;
        };
        let Some(mobile) = account.mobile.as_ref() else {
            self.show_notice(
                "В maFile нет identity_secret или device_id — подтверждения недоступны",
                true,
            );
            return;
        };
        let authorized = mobile.is_logged_in();
        self.ready_tab = ReadyTab::Confirmations;
        self.confirmation_account_filter = Some(index);
        self.confirmations.clear();
        if authorized {
            self.refresh_current_tab();
        } else {
            self.show_notice("Для подтверждений нужна отдельная авторизация Steam", false);
            self.open_steam_login(Some(index));
        }
    }

    fn steam_accounts(&self) -> Vec<(usize, steamguard::SteamGuardAccount)> {
        self.accounts
            .iter()
            .enumerate()
            .filter_map(|(index, account)| account.mobile.clone().map(|mobile| (index, mobile)))
            .collect()
    }

    fn refresh_current_tab(&mut self) {
        let request = match self.ready_tab {
            ReadyTab::Codes => return,
            ReadyTab::Confirmations => {
                let accounts = match self.confirmation_account_filter {
                    Some(index) => self
                        .accounts
                        .get(index)
                        .and_then(|account| account.mobile.clone())
                        .map(|account| vec![(index, account)])
                        .unwrap_or_default(),
                    None => self.steam_accounts(),
                };
                SteamRequest::LoadConfirmations(accounts)
            }
            ReadyTab::LoginRequests => SteamRequest::LoadLoginRequests(self.steam_accounts()),
        };
        if self.steam_tx.send(request).is_ok() {
            self.steam_busy = true;
        } else {
            self.show_notice("Фоновый модуль Steam остановлен", true);
        }
    }

    fn process_steam_events(&mut self) {
        while let Ok(event) = self.steam_rx.try_recv() {
            match event {
                SteamEvent::Working(message) => {
                    self.steam_busy = true;
                    if let Some(dialog) = self.add_dialog.as_mut()
                        && matches!(dialog.stage, AddStage::Credentials | AddStage::Working(_))
                    {
                        dialog.stage = AddStage::Working(message);
                    }
                }
                SteamEvent::NeedGuardCode {
                    device_code,
                    message,
                } => {
                    self.steam_busy = false;
                    if let Some(dialog) = self.add_dialog.as_mut() {
                        dialog.code.clear();
                        dialog.stage = AddStage::GuardCode {
                            message: if device_code {
                                message
                            } else {
                                format!("Код из письма: {message}")
                            },
                        };
                    }
                }
                SteamEvent::NeedExternalApproval(message) => {
                    self.steam_busy = true;
                    if let Some(dialog) = self.add_dialog.as_mut() {
                        dialog.stage = AddStage::ExternalApproval(message);
                    }
                }
                SteamEvent::NeedEnrollmentCode {
                    destination,
                    recovery_code,
                    draft_account,
                } => {
                    self.steam_busy = false;
                    let draft_account = *draft_account;
                    let saved_index = if let Some(index) =
                        self.accounts.iter().position(|current| {
                            current.steam_id.is_some() && current.steam_id == draft_account.steam_id
                        }) {
                        self.accounts[index] = draft_account;
                        index
                    } else {
                        self.accounts.push(draft_account);
                        self.accounts.len() - 1
                    };
                    if let Err(error) = self.save_vault() {
                        self.show_notice(
                            format!("Критическая ошибка сохранения секретов: {error}"),
                            true,
                        );
                    }
                    if let Some(dialog) = self.add_dialog.as_mut() {
                        dialog.code.clear();
                        dialog.result_index = Some(saved_index);
                        dialog.stage = AddStage::EnrollmentCode {
                            destination,
                            recovery_code,
                        };
                    }
                }
                SteamEvent::AuthenticatorAlreadyPresent => {
                    self.steam_busy = false;
                    if let Some(dialog) = self.add_dialog.as_mut() {
                        dialog.stage = AddStage::ExistingAuthenticator;
                    }
                }
                SteamEvent::NeedTransferCode => {
                    self.steam_busy = false;
                    if let Some(dialog) = self.add_dialog.as_mut() {
                        dialog.code.clear();
                        dialog.stage = AddStage::TransferCode;
                    }
                }
                SteamEvent::EnrollmentComplete {
                    replace_index,
                    account,
                    recovery_code,
                } => {
                    let account = *account;
                    self.steam_busy = false;
                    let saved_index = if let Some(index) = replace_index {
                        if index < self.accounts.len() {
                            self.accounts[index] = account;
                        }
                        index
                    } else if let Some(index) = self.accounts.iter().position(|current| {
                        current.steam_id.is_some() && current.steam_id == account.steam_id
                    }) {
                        self.accounts[index] = account;
                        index
                    } else {
                        self.accounts.push(account);
                        self.accounts.len() - 1
                    };
                    match self.save_vault() {
                        Ok(()) => {
                            if let Some(dialog) = self.add_dialog.as_mut() {
                                dialog.result_index = Some(saved_index);
                                dialog.stage = AddStage::Complete { recovery_code };
                            }
                            self.show_notice("Аккаунт Steam сохранён", false);
                            if self.ready_tab == ReadyTab::Confirmations
                                && self.confirmation_account_filter == Some(saved_index)
                            {
                                self.refresh_current_tab();
                            }
                        }
                        Err(error) => self.show_notice(error, true),
                    }
                }
                SteamEvent::ConfirmationsLoaded(rows) => {
                    self.steam_busy = false;
                    self.confirmations = rows;
                    self.show_notice("Подтверждения обновлены", false);
                }
                SteamEvent::TradeDetailsLoaded {
                    load_id,
                    id,
                    details,
                } => {
                    if let Some(row) = self
                        .confirmations
                        .iter_mut()
                        .find(|row| row.load_id == load_id && row.id == id)
                    {
                        row.trade = Some(details);
                    }
                }
                SteamEvent::LoginRequestsLoaded(rows) => {
                    self.steam_busy = false;
                    self.login_requests = rows;
                    self.show_notice("Запросы входа обновлены", false);
                }
                SteamEvent::ActionComplete(message) => {
                    self.steam_busy = false;
                    self.show_notice(message, false);
                    self.refresh_current_tab();
                }
                SteamEvent::ConfirmationsBatchComplete { completed, errors } => {
                    self.steam_busy = false;
                    self.confirmations.retain(|row| {
                        !completed.iter().any(|target| {
                            target.load_id == row.load_id
                                && target.id == row.id
                                && target.nonce == row.nonce
                        })
                    });
                    let message = if errors.is_empty() {
                        format!("Обработано подтверждений: {}", completed.len())
                    } else {
                        format!(
                            "Обработано: {}. Не удалось обработать часть списка: {}",
                            completed.len(),
                            errors.join("; ")
                        )
                    };
                    self.show_notice(message, !errors.is_empty());
                }
                SteamEvent::Error(error) => {
                    self.steam_busy = false;
                    if let Some(dialog) = self.add_dialog.as_mut()
                        && matches!(dialog.stage, AddStage::Working(_))
                    {
                        dialog.stage = AddStage::Credentials;
                    }
                    self.show_notice(error, true);
                }
            }
        }
    }

    fn export_mafile(&mut self, index: usize) {
        let Some(account) = self.accounts.get(index) else {
            return;
        };
        let Some(mobile) = account.mobile.as_ref() else {
            self.show_notice(
                "В импортированном файле недостаточно данных для экспорта",
                true,
            );
            return;
        };
        let suggested = format!("{}.maFile", mobile.steam_id);
        let Some(path) = rfd::FileDialog::new()
            .set_title("Сохранить резервный maFile")
            .set_file_name(&suggested)
            .add_filter("Steam maFile", &["maFile"])
            .save_file()
        else {
            return;
        };
        let mut value = match serde_json::to_value(mobile) {
            Ok(value) => value,
            Err(error) => {
                self.show_notice(format!("Не удалось подготовить maFile: {error}"), true);
                return;
            }
        };
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "SteamID".to_owned(),
                serde_json::Value::String(mobile.steam_id.to_string()),
            );
            object.insert("fully_enrolled".to_owned(), serde_json::Value::Bool(true));
        }
        let result = serde_json::to_vec_pretty(&value)
            .map_err(|error| error.to_string())
            .and_then(|bytes| fs::write(&path, bytes).map_err(|error| error.to_string()));
        match result {
            Ok(()) => self.show_notice(format!("maFile сохранён: {}", path.display()), false),
            Err(error) => self.show_notice(format!("Не удалось сохранить maFile: {error}"), true),
        }
    }

    fn ui_setup(&mut self, ctx: &egui::Context) {
        let card_center = ctx.available_rect().center();
        auth_background(ctx);
        egui::Area::new(egui::Id::new("setup_card"))
            .fixed_pos(card_center)
            .pivot(egui::Align2::CENTER_CENTER)
            .show(ctx, |ui| {
                auth_card(ui, 420.0, |ui| {
                    auth_kicker(ui, "PRIVATE · LOCAL");
                    ui.add_space(22.0);
                    auth_heading(
                        ui,
                        "Создайте хранилище",
                        "Ваше личное пространство для Steam Guard.",
                    );
                    ui.add_space(26.0);
                    field_label(ui, "Мастер-пароль");
                    let first = ui.add_sized(
                        [ui.available_width(), 44.0],
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .horizontal_align(egui::Align::Center)
                            .vertical_align(egui::Align::Center)
                            .hint_text("Минимум 8 символов"),
                    );
                    ui.add_space(14.0);
                    field_label(ui, "Повторите пароль");
                    let second = ui.add_sized(
                        [ui.available_width(), 44.0],
                        egui::TextEdit::singleline(&mut self.password_repeat)
                            .password(true)
                            .horizontal_align(egui::Align::Center)
                            .vertical_align(egui::Align::Center)
                            .hint_text("Введите пароль ещё раз"),
                    );
                    ui.add_space(22.0);
                    let submit = ui.add_sized(
                        [ui.available_width(), 46.0],
                        primary_button("Создать хранилище"),
                    );
                    if submit.clicked()
                        || ((first.lost_focus() || second.lost_focus())
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                    {
                        self.create_vault();
                    }
                    ui.add_space(18.0);
                    security_note(
                        ui,
                        "У каждого пользователя свой пароль и отдельное локальное хранилище.",
                    );
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(
                                "Пароль нельзя восстановить — сохраните резервные maFiles",
                            )
                            .size(10.0)
                            .color(subtle()),
                        );
                    });
                });
            });
    }

    fn ui_locked(&mut self, ctx: &egui::Context) {
        let card_center = ctx.available_rect().center();
        auth_background(ctx);
        egui::Area::new(egui::Id::new("unlock_card"))
            .fixed_pos(card_center)
            .pivot(egui::Align2::CENTER_CENTER)
            .show(ctx, |ui| {
                auth_card(ui, 400.0, |ui| {
                    auth_kicker(ui, "ENCRYPTED VAULT");
                    ui.add_space(22.0);
                    auth_heading(
                        ui,
                        "С возвращением",
                        "Введите мастер-пароль, чтобы открыть хранилище.",
                    );
                    ui.add_space(26.0);
                    field_label(ui, "Мастер-пароль");
                    let password = ui.add_sized(
                        [ui.available_width(), 44.0],
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .horizontal_align(egui::Align::Center)
                            .vertical_align(egui::Align::Center)
                            .hint_text("Введите пароль"),
                    );
                    ui.add_space(18.0);
                    let unlock = ui.add_sized(
                        [ui.available_width(), 46.0],
                        primary_button("Открыть хранилище"),
                    );
                    if unlock.clicked()
                        || (password.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                    {
                        self.unlock();
                    }
                });
            });
    }

    fn ui_ready(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });
        if !dropped.is_empty() {
            self.import_paths(dropped);
        }

        egui::SidePanel::left("navigation")
            .exact_width(228.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(sidebar())
                    .inner_margin(egui::Margin::same(22))
                    .stroke(Stroke::new(1.0_f32, border())),
            )
            .show(ctx, |ui| {
                sidebar_identity(ui, self.accounts.len());
                ui.add_space(30.0);
                ui.label(
                    RichText::new("РАБОЧЕЕ ПРОСТРАНСТВО")
                        .size(11.0)
                        .strong()
                        .color(subtle()),
                );
                ui.add_space(10.0);
                if nav_button(
                    ui,
                    self.ready_tab == ReadyTab::Codes,
                    "01",
                    "Guard-коды",
                    None,
                )
                .clicked()
                {
                    self.ready_tab = ReadyTab::Codes;
                }
                if nav_button(
                    ui,
                    self.ready_tab == ReadyTab::Confirmations,
                    "02",
                    "Подтверждения",
                    Some(self.confirmations.len()),
                )
                .clicked()
                {
                    self.ready_tab = ReadyTab::Confirmations;
                    self.confirmation_account_filter = None;
                    self.confirmations.clear();
                    self.refresh_current_tab();
                }
                if nav_button(
                    ui,
                    self.ready_tab == ReadyTab::LoginRequests,
                    "03",
                    "Запросы входа",
                    Some(self.login_requests.len()),
                )
                .clicked()
                {
                    self.ready_tab = ReadyTab::LoginRequests;
                    self.refresh_current_tab();
                }

                ui.add_space(28.0);
                ui.label(
                    RichText::new("АККАУНТЫ")
                        .size(11.0)
                        .strong()
                        .color(subtle()),
                );
                ui.add_space(10.0);
                let import_button = primary_button("+  Добавить аккаунт")
                    .min_size(Vec2::new(ui.available_width(), 42.0));
                egui::containers::menu::MenuButton::from_button(import_button).ui(ui, |ui| {
                    ui.set_min_width(210.0);
                    ui.label(
                        RichText::new("СПОСОБ ДОБАВЛЕНИЯ")
                            .size(9.0)
                            .strong()
                            .color(subtle()),
                    );
                    ui.add_space(4.0);
                    if ui
                        .add_sized(
                            [ui.available_width(), 38.0],
                            egui::Button::new("Через Steam"),
                        )
                        .clicked()
                    {
                        ui.close();
                        self.open_steam_login(None);
                    }
                    if ui
                        .add_sized(
                            [ui.available_width(), 38.0],
                            egui::Button::new("Выбрать maFile"),
                        )
                        .clicked()
                    {
                        ui.close();
                        self.pick_files();
                    }
                    if ui
                        .add_sized(
                            [ui.available_width(), 38.0],
                            egui::Button::new("Импортировать папку"),
                        )
                        .clicked()
                    {
                        ui.close();
                        self.pick_folder();
                    }
                });

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if ui
                        .add_sized(
                            [ui.available_width(), 40.0],
                            egui::Button::new("Закрыть хранилище"),
                        )
                        .clicked()
                    {
                        self.lock();
                    }
                    ui.add_space(12.0);
                    local_security_badge(ui);
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(background())
                    .inner_margin(egui::Margin::same(28)),
            )
            .show(ctx, |ui| match self.ready_tab {
                ReadyTab::Codes => {
                    paint_ambient(ui);
                    self.codes_ui(ui, ctx);
                }
                ReadyTab::Confirmations => {
                    paint_ambient(ui);
                    self.confirmations_ui(ui);
                }
                ReadyTab::LoginRequests => {
                    paint_ambient(ui);
                    self.login_requests_ui(ui);
                }
            });

        self.delete_dialog(ctx);
        self.add_steam_dialog(ctx);
    }

    fn codes_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("SECURE CODES")
                        .size(10.0)
                        .strong()
                        .color(accent()),
                );
                ui.heading(RichText::new("Коды доступа").size(28.0).strong());
                ui.add_space(3.0);
                ui.label(
                    RichText::new("Нажмите на код, чтобы скопировать его")
                        .size(13.0)
                        .color(muted()),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_sized(
                    [260.0_f32.min(ui.available_width()), 42.0],
                    egui::TextEdit::singleline(&mut self.search)
                        .horizontal_align(egui::Align::Center)
                        .vertical_align(egui::Align::Center)
                        .hint_text("Поиск аккаунта"),
                );
            });
        });
        ui.add_space(24.0);
        if self.accounts.is_empty() {
            empty_state(ui);
            return;
        }
        let now_precise = unix_time_precise();
        let now = now_precise.floor() as u64;
        let remaining_precise = (30.0 - now_precise.rem_euclid(30.0)) as f32;
        let query = self.search.trim().to_lowercase();
        let visible: Vec<usize> = self
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, account)| query.is_empty() || account.name.to_lowercase().contains(&query))
            .map(|(index, _)| index)
            .collect();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .show(ui, |ui| {
                let gap = ui.spacing().item_spacing.x;
                let card_width = ((ui.available_width() - gap - 2.0) / 2.0).max(300.0);
                for row in visible.chunks(2) {
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                        for &index in row {
                            self.account_card(ui, ctx, index, now, remaining_precise, card_width);
                        }
                    });
                    ui.add_space(12.0);
                }
                ui.add_space(20.0);
            });
    }

    fn confirmations_ui(&mut self, ui: &mut egui::Ui) {
        let rows = self.confirmations.clone();
        let title = if let Some(account) = self
            .confirmation_account_filter
            .and_then(|index| self.accounts.get(index))
        {
            format!("Подтверждения · {} · {}", account.name, rows.len())
        } else {
            format!("Подтверждения · {}", rows.len())
        };
        section_header(
            ui,
            &title,
            "Обмены, торговая площадка, Steam Family и действия с аккаунтом",
            self.steam_busy,
        );
        let mut refresh = false;
        let mut authorize = None;
        let mut bulk_action = None;
        let mut expand_all = None;
        ui.horizontal_wrapped(|ui| {
            refresh = ui
                .add_enabled(!self.steam_busy, egui::Button::new("Обновить"))
                .clicked();
            ui.add_enabled_ui((!self.steam_busy) && !rows.is_empty(), |ui| {
                ui.menu_button("Действия со списком", |ui| {
                    for (title, scope, accept) in [
                        ("Принять все", ConfirmationScope::All, true),
                        ("Принять все трейды", ConfirmationScope::Trades, true),
                        ("Принять все продажи", ConfirmationScope::Sales, true),
                        ("Отклонить все трейды", ConfirmationScope::Trades, false),
                        ("Отклонить все продажи", ConfirmationScope::Sales, false),
                    ] {
                        let count = rows.iter().filter(|row| scope.matches(row)).count();
                        if ui
                            .add_enabled(count > 0, egui::Button::new(format!("{title} · {count}")))
                            .clicked()
                        {
                            bulk_action = Some((scope, accept));
                            ui.close();
                        }
                    }
                });
            });
            if rows.iter().any(|row| row.is_trade) {
                ui.menu_button("Предметы", |ui| {
                    if ui.button("Развернуть все").clicked() {
                        expand_all = Some(true);
                        ui.close();
                    }
                    if ui.button("Свернуть все").clicked() {
                        expand_all = Some(false);
                        ui.close();
                    }
                });
            }
            if let Some(index) = self.confirmation_account_filter {
                if ui.button("Все аккаунты").clicked() {
                    self.confirmation_account_filter = None;
                    self.confirmations.clear();
                    refresh = true;
                }
                if ui.button("Авторизация Steam").clicked() {
                    authorize = Some(index);
                }
            }
        });
        ui.add_space(10.0);
        let output = confirmation_list_ui(ui, &rows, &self.accounts, !self.steam_busy, expand_all);
        if refresh {
            self.refresh_current_tab();
        }
        if let Some(index) = authorize {
            self.open_steam_login(Some(index));
        }
        if let Some((scope, accept)) = bulk_action {
            self.apply_confirmation_actions(
                rows.into_iter().filter(|row| scope.matches(row)).collect(),
                accept,
                true,
            );
        } else if let Some((row, accept)) = output.inner {
            self.apply_confirmation_actions(vec![row], accept, false);
        }
    }

    fn apply_confirmation_actions(&mut self, rows: Vec<ConfirmationRow>, accept: bool, bulk: bool) {
        if rows.is_empty() {
            return;
        }
        if self.steam_busy {
            return;
        }
        let request = if bulk {
            match prepare_confirmation_groups(&self.accounts, &rows) {
                Ok(groups) => SteamRequest::RespondConfirmations { groups, accept },
                Err(error) => {
                    self.show_notice(error, true);
                    return;
                }
            }
        } else {
            let row = &rows[0];
            let Some(account) = self
                .accounts
                .get(row.account_index)
                .and_then(|account| account.mobile.clone())
            else {
                self.show_notice("Аккаунт подтверждения недоступен", true);
                return;
            };
            SteamRequest::RespondConfirmation {
                account,
                id: row.id.clone(),
                nonce: row.nonce.clone(),
                accept,
            }
        };
        if self.steam_tx.send(request).is_ok() {
            self.steam_busy = true;
        } else {
            self.show_notice("Фоновый модуль Steam остановлен", true);
        }
    }

    fn login_requests_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Запросы входа",
            "Подтверждайте только те устройства и адреса, которые узнаёте",
            self.steam_busy,
        );
        let refresh = ui
            .add_enabled(!self.steam_busy, egui::Button::new("Обновить"))
            .clicked();
        ui.add_space(16.0);
        if self.login_requests.is_empty() {
            info_empty(
                ui,
                "Новых запросов входа нет",
                "Откройте этот раздел после попытки входа на другом устройстве.",
            );
        }
        let rows = self.login_requests.clone();
        let mut action = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in rows {
                let account_name = self
                    .accounts
                    .get(row.account_index)
                    .map(|account| account.name.as_str())
                    .unwrap_or("Steam");
                let stroke = if row.warning { danger() } else { border() };
                egui::Frame::new()
                    .fill(card())
                    .stroke(Stroke::new(1.0_f32, stroke))
                    .corner_radius(CornerRadius::same(12))
                    .inner_margin(egui::Margin::same(18))
                    .show(ui, |ui| {
                        ui.label(RichText::new(account_name).small().color(accent()));
                        ui.label(RichText::new(&row.device).size(17.0).strong());
                        ui.label(RichText::new(format!("IP: {}", row.ip)).color(muted()));
                        if !row.location.is_empty() {
                            ui.label(
                                RichText::new(format!("Местоположение: {}", row.location))
                                    .color(muted()),
                            );
                        }
                        if row.warning {
                            ui.label(
                                RichText::new(
                                    "Steam отметил необычное местоположение или активность",
                                )
                                .color(danger()),
                            );
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(!self.steam_busy, primary_button("Разрешить вход"))
                                .clicked()
                            {
                                action = Some((row.clone(), true));
                            }
                            if ui
                                .add_enabled(
                                    !self.steam_busy,
                                    egui::Button::new(RichText::new("Отклонить").color(danger())),
                                )
                                .clicked()
                            {
                                action = Some((row.clone(), false));
                            }
                        });
                    });
                ui.add_space(10.0);
            }
        });
        if refresh {
            self.refresh_current_tab();
        }
        if let Some((row, accept)) = action
            && let Some(account) = self
                .accounts
                .get(row.account_index)
                .and_then(|account| account.mobile.clone())
            && self
                .steam_tx
                .send(SteamRequest::RespondLogin {
                    account,
                    client_id: row.client_id,
                    version: row.version,
                    accept,
                })
                .is_ok()
        {
            self.steam_busy = true;
        }
    }

    fn add_steam_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.add_dialog.take() else {
            return;
        };
        let mut keep_open = true;
        let mut command = None;
        let mut export_index = None;
        let (dialog_title, dialog_subtitle) = match &dialog.stage {
            AddStage::Credentials if dialog.existing_index.is_some() => {
                ("Авторизация Steam", "Подключение сессии для подтверждений")
            }
            AddStage::Credentials => ("Добавить аккаунт", "Безопасное подключение к Steam"),
            AddStage::Working(_) | AddStage::ExternalApproval(_) => {
                ("Подключение к Steam", "Защищённый обмен данными")
            }
            AddStage::GuardCode { .. } => ("Проверка входа", "Подтвердите владение аккаунтом"),
            AddStage::EnrollmentCode { .. } => ("Активация Steam Guard", "Последний шаг настройки"),
            AddStage::ExistingAuthenticator => {
                ("Steam Guard уже активен", "Выберите способ продолжения")
            }
            AddStage::TransferCode => ("Перенос аутентификатора", "Подтверждение по SMS"),
            AddStage::Complete { .. } => ("Готово", "Аккаунт защищён и добавлен"),
        };

        modal_backdrop(ctx, "steam_dialog_backdrop");
        egui::Area::new(egui::Id::new("steam_dialog"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                modal_card(ui, 440.0, |ui| {
                    if modal_header(ui, "STEAM CONNECTION", dialog_title, dialog_subtitle) {
                        keep_open = false;
                    }
                    ui.add_space(24.0);
                match &dialog.stage {
                    AddStage::Credentials => {
                        if dialog.existing_index.is_some() {
                            ui.label(
                                RichText::new("Отдельная авторизация для подтверждений")
                                    .strong()
                                    .color(accent()),
                            );
                            ui.label("Как и в SDA, после импорта maFile нужно войти в Steam внутри приложения. Это сохранит зашифрованную Steam-сессию, но не изменит аутентификатор.");
                            ui.add_space(6.0);
                        }
                        ui.label("Пароль отправляется только в Steam и не сохраняется.");
                        ui.add_space(10.0);
                        field_label(ui, "Логин Steam");
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::TextEdit::singleline(&mut dialog.username)
                                .horizontal_align(egui::Align::Center)
                                .vertical_align(egui::Align::Center),
                        );
                        ui.add_space(8.0);
                        field_label(ui, "Пароль Steam");
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::TextEdit::singleline(&mut dialog.password)
                                .password(true)
                                .horizontal_align(egui::Align::Center)
                                .vertical_align(egui::Align::Center),
                        );
                        ui.add_space(12.0);
                        if ui
                            .add_sized(
                                [ui.available_width(), 44.0],
                                primary_button("Войти в Steam"),
                            )
                            .clicked()
                        {
                            if dialog.username.trim().is_empty() || dialog.password.is_empty() {
                                self.show_notice("Введите логин и пароль Steam", true);
                            } else {
                                let existing = dialog.existing_index.and_then(|index| {
                                    self.accounts
                                        .get(index)
                                        .and_then(|account| account.mobile.clone())
                                        .map(|account| (index, account))
                                });
                                command = Some(SteamRequest::BeginEnrollment {
                                    username: dialog.username.trim().to_lowercase(),
                                    password: std::mem::take(&mut dialog.password),
                                    existing,
                                });
                                dialog.stage = AddStage::Working("Подключаемся к Steam…".to_owned());
                            }
                        }
                    }
                    AddStage::Working(message) => {
                        modal_status(ui, message, "Обычно это занимает несколько секунд");
                    }
                    AddStage::GuardCode { message } => {
                        ui.label(message);
                        ui.add_space(10.0);
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::TextEdit::singleline(&mut dialog.code)
                                .horizontal_align(egui::Align::Center)
                                .vertical_align(egui::Align::Center)
                                .hint_text("Код Steam Guard"),
                        );
                        ui.add_space(10.0);
                        if ui
                            .add_sized(
                                [ui.available_width(), 44.0],
                                primary_button("Продолжить"),
                            )
                            .clicked()
                            && !dialog.code.trim().is_empty()
                        {
                            command = Some(SteamRequest::SubmitGuardCode(std::mem::take(&mut dialog.code)));
                        }
                    }
                    AddStage::ExternalApproval(message) => {
                        modal_status(ui, message, "Ожидаем подтверждение в Steam…");
                    }
                    AddStage::EnrollmentCode { destination, recovery_code } => {
                        ui.label(destination);
                        ui.add_space(8.0);
                        ui.label(RichText::new("Сначала сохраните код восстановления:").color(danger()));
                        if ui
                            .button(RichText::new(recovery_code).monospace().size(18.0))
                            .clicked()
                        {
                            ctx.copy_text(recovery_code.clone());
                        }
                        ui.label(RichText::new("Он нужен для аварийного удаления Steam Guard.").small().color(muted()));
                        if ui.button("Сохранить резервный maFile сейчас").clicked() {
                            export_index = dialog.result_index;
                        }
                        ui.add_space(10.0);
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::TextEdit::singleline(&mut dialog.code)
                                .horizontal_align(egui::Align::Center)
                                .vertical_align(egui::Align::Center)
                                .hint_text("Код подтверждения"),
                        );
                        ui.add_space(10.0);
                        if ui
                            .add_sized(
                                [ui.available_width(), 44.0],
                                primary_button("Активировать"),
                            )
                            .clicked()
                            && !dialog.code.trim().is_empty()
                        {
                            command = Some(SteamRequest::FinalizeEnrollment(std::mem::take(&mut dialog.code)));
                        }
                    }
                    AddStage::ExistingAuthenticator => {
                        ui.label(RichText::new("На аккаунте уже есть мобильный аутентификатор").strong());
                        ui.label("Steam не выдаёт его секреты после входа. Можно перенести аутентификатор по SMS, но Steam обычно вводит ограничение на обмены после переноса.");
                        ui.add_space(10.0);
                        if ui
                            .add_sized(
                                [ui.available_width(), 44.0],
                                primary_button("Перенести по SMS"),
                            )
                            .clicked()
                        {
                            command = Some(SteamRequest::BeginTransfer);
                        }
                    }
                    AddStage::TransferCode => {
                        ui.label("Введите код из SMS для завершения переноса.");
                        ui.add_sized(
                            [ui.available_width(), 40.0],
                            egui::TextEdit::singleline(&mut dialog.code)
                                .horizontal_align(egui::Align::Center)
                                .vertical_align(egui::Align::Center)
                                .hint_text("Код из SMS"),
                        );
                        ui.add_space(10.0);
                        if ui
                            .add_sized(
                                [ui.available_width(), 44.0],
                                primary_button("Завершить перенос"),
                            )
                            .clicked()
                            && !dialog.code.trim().is_empty()
                        {
                            command = Some(SteamRequest::SubmitTransferCode(std::mem::take(&mut dialog.code)));
                        }
                    }
                    AddStage::Complete { recovery_code } => {
                        ui.label(RichText::new("Аккаунт добавлен").size(20.0).strong().color(success()));
                        if !recovery_code.is_empty() {
                            ui.label("Код восстановления:");
                            if ui.button(RichText::new(recovery_code).monospace().size(18.0)).clicked() {
                                ctx.copy_text(recovery_code.clone());
                            }
                        }
                        ui.add_space(10.0);
                        if ui.button("Сохранить резервный maFile").clicked() {
                            export_index = dialog.result_index;
                        }
                        if ui
                            .add_sized([ui.available_width(), 44.0], primary_button("Готово"))
                            .clicked()
                        {
                            keep_open = false;
                        }
                    }
                }
                });
            });
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            keep_open = false;
        }
        if let Some(request) = command {
            if self.steam_tx.send(request).is_ok() {
                self.steam_busy = true;
            } else {
                self.show_notice("Фоновый модуль Steam остановлен", true);
            }
        }
        if keep_open {
            self.add_dialog = Some(dialog);
        } else {
            dialog.password.zeroize();
            dialog.code.zeroize();
        }
        if let Some(index) = export_index {
            self.export_mafile(index);
        }
    }

    fn account_card(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        index: usize,
        now: u64,
        remaining_precise: f32,
        width: f32,
    ) {
        let name = self.accounts[index].name.clone();
        let steam_id = self.accounts[index].steam_id.clone();
        let code = steam_guard_code(&self.accounts[index].shared_secret, now);
        let has_mobile = self.accounts[index].mobile.is_some();
        let is_authorized = self.accounts[index]
            .mobile
            .as_ref()
            .is_some_and(steamguard::SteamGuardAccount::is_logged_in);
        let remaining_seconds = remaining_precise.ceil() as u64;
        let mut open_session = false;
        let mut open_confirmations = false;
        let mut export_mafile = false;
        let mut delete = false;

        let card_response = egui::Frame::new()
            .fill(card())
            .stroke(Stroke::new(1.0_f32, border()))
            .corner_radius(CornerRadius::same(16))
            .inner_margin(egui::Margin::same(14))
            .shadow(egui::epaint::Shadow {
                offset: [0, 8],
                blur: 24,
                spread: 0,
                color: Color32::from_black_alpha(55),
            })
            .show(ui, |ui| {
                let content_width = width - 28.0;
                let actions_width = 106.0;
                let column_gap = 10.0;
                let left_width = content_width - actions_width - column_gap;
                ui.set_width(content_width);
                ui.set_min_height(146.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = column_gap;
                    ui.vertical(|ui| {
                        ui.set_width(left_width);
                        ui.label(RichText::new("LOGIN").size(8.0).strong().color(accent()));
                        ui.label(RichText::new(&name).size(16.0).strong());
                        if let Some(steam_id) = &steam_id {
                            ui.label(
                                RichText::new(steam_id)
                                    .monospace()
                                    .size(9.0)
                                    .color(subtle()),
                            );
                        } else {
                            ui.label(
                                RichText::new("SteamID не указан")
                                    .size(10.0)
                                    .color(subtle()),
                            );
                        }
                        ui.add_space(10.0);
                        match &code {
                            Ok(code) => {
                                let response = egui::Frame::new()
                                    .fill(elevated())
                                    .stroke(Stroke::new(1.0_f32, border()))
                                    .corner_radius(CornerRadius::same(11))
                                    .inner_margin(egui::Margin::symmetric(10, 7))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.vertical_centered(|ui| {
                                            ui.label(
                                                RichText::new(code)
                                                    .monospace()
                                                    .size(22.0)
                                                    .strong()
                                                    .color(accent()),
                                            );
                                        });
                                    })
                                    .response
                                    .interact(egui::Sense::click())
                                    .on_hover_text("Нажмите, чтобы скопировать");
                                if response.clicked() {
                                    ctx.copy_text(code.clone());
                                    self.show_notice("Код скопирован", false);
                                }
                            }
                            Err(_) => {
                                ui.label(RichText::new("Ошибка секрета").color(danger()));
                            }
                        }
                        ui.add_space(8.0);
                        let progress = remaining_precise / 30.0;
                        ui.horizontal(|ui| {
                            smooth_progress_bar(
                                ui,
                                progress,
                                (ui.available_width() - 38.0).max(60.0),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(format!("{remaining_seconds}с"))
                                            .monospace()
                                            .size(10.0)
                                            .color(subtle()),
                                    );
                                },
                            );
                        });
                    });

                    ui.vertical(|ui| {
                        ui.set_width(actions_width);
                        ui.spacing_mut().item_spacing.y = 6.0;
                        if has_mobile {
                            let session_text = if is_authorized {
                                RichText::new("Сессия · OK").size(10.0).color(success())
                            } else {
                                RichText::new("Сессия").size(10.0)
                            };
                            if ui
                                .add_sized(
                                    [ui.available_width(), 30.0],
                                    egui::Button::new(session_text),
                                )
                                .on_hover_text("Авторизация нужна для подтверждений")
                                .clicked()
                            {
                                open_session = true;
                            }
                            if ui
                                .add_sized(
                                    [ui.available_width(), 30.0],
                                    egui::Button::new(RichText::new("maFile").size(10.0)),
                                )
                                .clicked()
                            {
                                export_mafile = true;
                            }
                        } else {
                            ui.add_enabled_ui(false, |ui| {
                                ui.add_sized(
                                    [ui.available_width(), 30.0],
                                    egui::Button::new(RichText::new("Нет сессии").size(10.0)),
                                );
                                ui.add_sized(
                                    [ui.available_width(), 30.0],
                                    egui::Button::new(RichText::new("Нет maFile").size(10.0)),
                                );
                            });
                        }
                        if ui
                            .add_sized(
                                [ui.available_width(), 30.0],
                                egui::Button::new(RichText::new("Подтверждения").size(10.0)),
                            )
                            .on_hover_text("Открыть подтверждения этого аккаунта")
                            .clicked()
                        {
                            open_confirmations = true;
                        }
                        if ui
                            .add_sized(
                                [ui.available_width(), 30.0],
                                egui::Button::new(
                                    RichText::new("Удалить").size(11.0).color(danger()),
                                ),
                            )
                            .clicked()
                        {
                            delete = true;
                        }
                    });
                });
            });
        let rect = card_response.response.rect;
        ui.painter().line_segment(
            [
                egui::pos2(rect.left() + 18.0, rect.top()),
                egui::pos2(rect.right() - 18.0, rect.top()),
            ],
            Stroke::new(1.5_f32, Color32::from_rgba_unmultiplied(181, 154, 255, 120)),
        );

        if open_session {
            self.open_steam_login(Some(index));
        }
        if export_mafile {
            self.export_mafile(index);
        }
        if open_confirmations {
            self.open_account_confirmations(index);
        }
        if delete {
            self.pending_delete = Some(index);
        }
    }

    fn delete_dialog(&mut self, ctx: &egui::Context) {
        let Some(index) = self.pending_delete else {
            return;
        };
        let name = self
            .accounts
            .get(index)
            .map(|account| account.name.clone())
            .unwrap_or_default();

        modal_backdrop(ctx, "delete_dialog_backdrop");
        egui::Area::new(egui::Id::new("delete_dialog"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                modal_card(ui, 380.0, |ui| {
                    if modal_header(
                        ui,
                        "DANGER ZONE",
                        "Удалить аккаунт?",
                        "Это действие нельзя отменить",
                    ) {
                        self.pending_delete = None;
                    }
                    ui.add_space(22.0);
                    egui::Frame::new()
                        .fill(Color32::from_rgba_unmultiplied(248, 113, 132, 9))
                        .stroke(Stroke::new(
                            1.0_f32,
                            Color32::from_rgba_unmultiplied(248, 113, 132, 55),
                        ))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(egui::Margin::same(14))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(&name).size(16.0).strong());
                            ui.label(
                                RichText::new("Будет удалён из зашифрованного хранилища")
                                    .size(12.0)
                                    .color(muted()),
                            );
                        });
                    ui.add_space(18.0);
                    ui.columns(2, |columns| {
                        if columns[0]
                            .add_sized(
                                [columns[0].available_width(), 42.0],
                                egui::Button::new("Отмена"),
                            )
                            .clicked()
                        {
                            self.pending_delete = None;
                        }
                        if columns[1]
                            .add_sized(
                                [columns[1].available_width(), 42.0],
                                egui::Button::new(
                                    RichText::new("Удалить").strong().color(Color32::WHITE),
                                )
                                .fill(danger())
                                .stroke(Stroke::NONE),
                            )
                            .clicked()
                        {
                            if index < self.accounts.len() {
                                let mut removed = self.accounts.remove(index);
                                removed.shared_secret.zeroize();
                                match self.save_vault() {
                                    Ok(()) => self.show_notice("Аккаунт удалён", false),
                                    Err(error) => self.show_notice(error, true),
                                }
                            }
                            self.pending_delete = None;
                        }
                    });
                });
            });
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.pending_delete = None;
        }
    }

    fn notice_ui(&mut self, ctx: &egui::Context) {
        let Some(notice) = &self.notice else {
            return;
        };
        let lifetime = if notice.error {
            Duration::from_secs(12)
        } else {
            Duration::from_secs(4)
        };
        if notice.created.elapsed() > lifetime {
            self.notice = None;
            return;
        }

        let color = if notice.error { danger() } else { accent() };
        egui::Area::new(egui::Id::new("notice"))
            .anchor(egui::Align2::CENTER_BOTTOM, Vec2::new(0.0, -18.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(elevated())
                    .stroke(Stroke::new(1.0_f32, color))
                    .corner_radius(CornerRadius::same(9))
                    .inner_margin(egui::Margin::symmetric(16, 10))
                    .show(ui, |ui| {
                        ui.set_max_width((ctx.screen_rect().width() - 48.0).min(720.0));
                        ui.add(
                            egui::Label::new(RichText::new(&notice.text).color(Color32::WHITE))
                                .wrap(),
                        );
                    });
            });
    }
}

fn confirmation_list_ui(
    ui: &mut egui::Ui,
    rows: &[ConfirmationRow],
    accounts: &[Account],
    enabled: bool,
    expand_all: Option<bool>,
) -> egui::scroll_area::ScrollAreaOutput<Option<(ConfirmationRow, bool)>> {
    egui::ScrollArea::vertical()
        .id_salt("confirmation_list")
        .auto_shrink([false, false])
        .max_height(ui.available_height())
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .show(ui, |ui| {
            let mut action = None;
            if rows.is_empty() { info_empty(ui, "Нет ожидающих подтверждений", "Для импортированного maFile сначала авторизуйте аккаунт на карточке Guard-кода."); }
            for row in rows {
                let account_name = accounts.get(row.account_index).map(|account| account.name.as_str()).unwrap_or("Steam");
                ui.push_id(("confirmation", row.account_index, &row.id), |ui| {
                    let response = confirmation_card_ui(ui, row, account_name, enabled, expand_all);
                    if let Some(accept) = response.inner.action { action = Some((row.clone(), accept)); }
                });
                ui.add_space(6.0);
            }
            action
        })
}

struct ConfirmationCardResult {
    action: Option<bool>,
    #[cfg(test)]
    action_rects: [egui::Rect; 2],
}

fn confirmation_action_buttons_ui(
    ui: &mut egui::Ui,
    enabled: bool,
) -> (Option<bool>, [egui::Rect; 2]) {
    let accept = ui
        .add_enabled_ui(enabled, |ui| {
            ui.add_sized(
                [96.0, 30.0],
                primary_button("Принять").wrap_mode(egui::TextWrapMode::Extend),
            )
        })
        .inner;
    let reject = ui
        .add_enabled_ui(enabled, |ui| {
            ui.add_sized(
                [96.0, 30.0],
                egui::Button::new(RichText::new("Отклонить").color(danger()))
                    .wrap_mode(egui::TextWrapMode::Extend),
            )
        })
        .inner;
    let action = if accept.clicked() {
        Some(true)
    } else if reject.clicked() {
        Some(false)
    } else {
        None
    };
    (action, [accept.rect, reject.rect])
}

fn confirmation_card_ui(
    ui: &mut egui::Ui,
    row: &ConfirmationRow,
    account_name: &str,
    enabled: bool,
    expand: Option<bool>,
) -> egui::InnerResponse<ConfirmationCardResult> {
    egui::Frame::new()
        .fill(card())
        .stroke(Stroke::new(1.0_f32, border()))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.spacing_mut().button_padding = Vec2::new(10.0, 4.0);
            ui.spacing_mut().interact_size.y = 26.0;
            let (action, _action_rects) = ui
                .horizontal(|ui| {
                    let left_width =
                        (ui.available_width() - 192.0 - 2.0 * ui.spacing().item_spacing.x).max(0.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(left_width, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            if row.is_trade || row.is_market_sale {
                                let image = row
                                    .icon
                                    .as_deref()
                                    .and_then(steam_trade::steam_image_url)
                                    .or_else(|| {
                                        row.trade
                                            .as_ref()
                                            .and_then(|r| r.as_ref().ok())
                                            .and_then(|trade| trade.avatar.clone())
                                    });
                                steam_picture(ui, image.as_deref(), 40.0, row.is_trade);
                            }
                            ui.vertical(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&row.headline).size(16.0).strong(),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(&row.headline);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(format!("{account_name} · {}", row.kind))
                                            .small()
                                            .color(accent()),
                                    )
                                    .truncate(),
                                );
                                if !row.summary.is_empty() {
                                    let tooltip = if row.created > 0 {
                                        format!("{}\nСоздано: {}", row.summary, row.created)
                                    } else {
                                        row.summary.clone()
                                    };
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&row.summary).small().color(muted()),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(tooltip);
                                }
                            });
                        },
                    );
                    ui.allocate_ui_with_layout(
                        Vec2::new(200.0, 30.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| confirmation_action_buttons_ui(ui, enabled),
                    )
                    .inner
                })
                .inner;
            if row.is_trade {
                ui.add_space(4.0);
                let label = row
                    .trade
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map(|trade| {
                        format!(
                            "Предметы · Отдаёте: {} · Получаете: {}",
                            trade.giving.iter().map(|item| item.amount).sum::<u64>(),
                            trade.receiving.iter().map(|item| item.amount).sum::<u64>()
                        )
                    })
                    .unwrap_or_else(|| "Предметы обмена".to_owned());
                let header = egui::CollapsingHeader::new(label)
                    .id_salt("trade_items")
                    .default_open(false);
                let header = if let Some(open) = expand {
                    header.open(Some(open))
                } else {
                    header
                };
                header.show(ui, |ui| match &row.trade {
                    None => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new("Загружаем предметы обмена…").color(muted()));
                        });
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).color(danger()));
                    }
                    Some(Ok(trade)) => {
                        if let Some(id) = &trade.partner_id {
                            ui.hyperlink_to(
                                RichText::new(format!("Steam ID: {id}"))
                                    .small()
                                    .color(muted()),
                                format!("https://steamcommunity.com/profiles/{id}"),
                            );
                            ui.add_space(4.0);
                        }
                        if ui.available_width() >= 560.0 {
                            ui.columns(2, |columns| {
                                trade_items_ui(&mut columns[0], "Вы отдаёте", &trade.giving);
                                trade_items_ui(&mut columns[1], "Вы получаете", &trade.receiving);
                            });
                        } else {
                            trade_items_ui(ui, "Вы отдаёте", &trade.giving);
                            ui.add_space(6.0);
                            trade_items_ui(ui, "Вы получаете", &trade.receiving);
                        }
                    }
                });
            }
            ConfirmationCardResult {
                action,
                #[cfg(test)]
                action_rects: _action_rects,
            }
        })
}

fn prepare_confirmation_groups(
    accounts: &[Account],
    rows: &[ConfirmationRow],
) -> Result<Vec<ConfirmationGroup>, String> {
    let mut targets = std::collections::BTreeMap::<usize, Vec<ConfirmationTarget>>::new();
    for row in rows {
        targets
            .entry(row.account_index)
            .or_default()
            .push(ConfirmationTarget {
                load_id: row.load_id,
                id: row.id.clone(),
                nonce: row.nonce.clone(),
            });
    }
    targets
        .into_iter()
        .map(|(index, targets)| {
            let account = accounts
                .get(index)
                .and_then(|account| account.mobile.clone())
                .ok_or_else(|| "Аккаунт подтверждения недоступен. Обновите список".to_owned())?;
            Ok(ConfirmationGroup { account, targets })
        })
        .collect()
}

fn steam_picture(ui: &mut egui::Ui, url: Option<&str>, size: f32, avatar: bool) {
    if let Some(url) = url {
        ui.add(
            egui::Image::new(url)
                .fit_to_exact_size(Vec2::splat(size))
                .corner_radius(if avatar { size / 2.0 } else { 6.0 })
                .show_loading_spinner(true),
        );
    } else {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, if avatar { size / 2.0 } else { 6.0 }, border());
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            if avatar { "?" } else { "—" },
            egui::FontId::proportional(20.0),
            muted(),
        );
    }
}

fn trade_items_ui(ui: &mut egui::Ui, title: &str, items: &[steam_trade::TradeItem]) {
    let count: u64 = items.iter().map(|item| item.amount).sum();
    ui.label(RichText::new(format!("{title} · {count}")).strong());
    ui.add_space(6.0);
    if items.is_empty() {
        ui.label(RichText::new("Нет предметов").small().color(muted()));
    }
    for item in items {
        egui::Frame::new()
            .fill(background())
            .corner_radius(CornerRadius::same(8))
            .inner_margin(egui::Margin::same(8))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    steam_picture(ui, item.image.as_deref(), 56.0, false);
                    ui.vertical(|ui| {
                        let name = if item.amount > 1 {
                            format!("{} ×{}", item.name, item.amount)
                        } else {
                            item.name.clone()
                        };
                        ui.add(egui::Label::new(RichText::new(name).strong()).wrap());
                        ui.add(
                            egui::Label::new(RichText::new(&item.game).small().color(muted()))
                                .wrap(),
                        );
                    });
                });
            });
        ui.add_space(5.0);
    }
}

impl eframe::App for MortySteamAuthApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) && !self.exit_requested {
            if self.tray_icon.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.tray_popup = None;
                self.main_window_hidden = true;
            } else {
                self.exit_requested = true;
            }
        }

        if self.exit_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        let repaint_interval = if self.screen == Screen::Ready {
            Duration::from_millis(16)
        } else {
            Duration::from_millis(250)
        };
        ctx.request_repaint_after(repaint_interval);
        self.process_tray_actions(ctx);
        self.process_tray_events(ctx);
        if self.exit_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        self.process_steam_events();
        title_bar(ctx, &self.logo);
        match self.screen {
            Screen::Setup => self.ui_setup(ctx),
            Screen::Locked => self.ui_locked(ctx),
            Screen::Ready => self.ui_ready(ctx),
        }
        self.notice_ui(ctx);
        self.tray_popup_ui(ctx);

        if self.main_window_hidden {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        if self.exit_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

impl Drop for MortySteamAuthApp {
    fn drop(&mut self) {
        self.password.zeroize();
        self.password_repeat.zeroize();
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
        for account in &mut self.accounts {
            account.shared_secret.zeroize();
        }
    }
}

fn main() -> eframe::Result {
    let window_icon = eframe::icon_data::from_png_bytes(LOGO_BYTES)
        .expect("embedded logo.png must be a valid PNG");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_NAME)
            .with_icon(window_icon)
            .with_inner_size([980.0, 680.0])
            .with_decorations(false)
            .with_resizable(false)
            .with_maximize_button(false),
        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|cc| Ok(Box::new(MortySteamAuthApp::new(cc)))),
    )
}

fn vault_path() -> PathBuf {
    if let Some(legacy_dirs) = ProjectDirs::from("dev", "SteamVault", "SteamVault") {
        let legacy_path = legacy_dirs.data_local_dir().join("vault.json");
        if legacy_path.exists() {
            return legacy_path;
        }
    }

    ProjectDirs::from("app", "Morty", "MortySteamAuth")
        .map(|project_dirs| project_dirs.data_local_dir().join("vault.json"))
        .unwrap_or_else(|| PathBuf::from("vault.json"))
}

fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| format!("Не удалось создать ключ: {error}"))?;
    Ok(key)
}

fn save_vault(
    path: &Path,
    data: &VaultData,
    key: &[u8; 32],
    salt: &[u8; 16],
) -> Result<(), String> {
    let mut plaintext = serde_json::to_vec(data)
        .map_err(|error| format!("Не удалось подготовить данные: {error}"))?;
    let mut nonce_bytes = [0_u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|error| format!("Не удалось создать nonce: {error}"))?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|error| format!("Не удалось создать шифр: {error}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| "Не удалось зашифровать хранилище".to_owned())?;
    plaintext.zeroize();

    let envelope = VaultEnvelope {
        version: 1,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    };
    let encoded = serde_json::to_vec_pretty(&envelope)
        .map_err(|error| format!("Не удалось записать хранилище: {error}"))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Не удалось создать папку хранилища: {error}"))?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, encoded)
        .map_err(|error| format!("Не удалось сохранить хранилище: {error}"))?;

    if path.exists() {
        let backup = path.with_extension("bak");
        if backup.exists() {
            fs::remove_file(&backup)
                .map_err(|error| format!("Не удалось очистить резервную копию: {error}"))?;
        }
        fs::rename(path, &backup)
            .map_err(|error| format!("Не удалось подготовить обновление: {error}"))?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::rename(&backup, path);
            return Err(format!("Не удалось завершить сохранение: {error}"));
        }
        let _ = fs::remove_file(backup);
    } else {
        fs::rename(&temporary, path)
            .map_err(|error| format!("Не удалось завершить сохранение: {error}"))?;
    }
    Ok(())
}

fn load_vault(path: &Path, password: &str) -> Result<(VaultData, [u8; 32], [u8; 16]), String> {
    let bytes =
        fs::read(path).map_err(|error| format!("Не удалось прочитать хранилище: {error}"))?;
    let envelope: VaultEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| "Файл хранилища повреждён".to_owned())?;
    if envelope.version != 1 {
        return Err("Эта версия хранилища пока не поддерживается".to_owned());
    }

    let salt_vec = BASE64
        .decode(&envelope.salt)
        .map_err(|_| "Соль хранилища повреждена".to_owned())?;
    let salt: [u8; 16] = salt_vec
        .try_into()
        .map_err(|_| "Соль хранилища имеет неверный размер".to_owned())?;
    let nonce_vec = BASE64
        .decode(&envelope.nonce)
        .map_err(|_| "Nonce хранилища повреждён".to_owned())?;
    let nonce: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| "Nonce хранилища имеет неверный размер".to_owned())?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| "Данные хранилища повреждены".to_owned())?;

    let mut key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| format!("Не удалось создать шифр: {error}"))?;
    let mut plaintext = match cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref()) {
        Ok(value) => value,
        Err(_) => {
            key.zeroize();
            return Err("Неверный пароль или хранилище повреждено".to_owned());
        }
    };
    let data = serde_json::from_slice(&plaintext)
        .map_err(|_| "Расшифрованные данные повреждены".to_owned())?;
    plaintext.zeroize();
    Ok((data, key, salt))
}

fn parse_mafile(path: &Path) -> Result<Account, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{}: неверный JSON ({error})", path.display()))?;

    let shared_secret = json
        .get("shared_secret")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{}: отсутствует shared_secret", path.display()))?
        .to_owned();
    let decoded_secret = BASE64
        .decode(&shared_secret)
        .map_err(|_| format!("{}: shared_secret не является Base64", path.display()))?;
    if decoded_secret.len() != 20 {
        return Err(format!(
            "{}: shared_secret имеет неверную длину",
            path.display()
        ));
    }

    let steam_id = json_id(&json)
        .filter(|value| value != "0")
        .or_else(|| {
            json.get("Session")
                .and_then(json_id)
                .filter(|value| value != "0")
        })
        .or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .filter(|value| value.parse::<u64>().is_ok())
                .map(str::to_owned)
        });

    let name = json
        .get("account_name")
        .or_else(|| json.get("AccountName"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| steam_id.clone())
        .or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "Steam account".to_owned());

    let identity_secret = json
        .get("identity_secret")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !identity_secret.is_empty() {
        let identity_bytes = BASE64
            .decode(&identity_secret)
            .map_err(|_| format!("{}: identity_secret не является Base64", path.display()))?;
        if identity_bytes.is_empty() {
            return Err(format!("{}: identity_secret пуст", path.display()));
        }
    }
    let mut device_id = json
        .get("device_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let parsed_steam_id = steam_id
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    if device_id.is_empty()
        && let Some(numeric_steam_id) = parsed_steam_id
    {
        device_id = steam_device_id(numeric_steam_id);
    }
    let mobile = if let Some(numeric_steam_id) = parsed_steam_id
        && !identity_secret.is_empty()
    {
        let tokens = json
            .get("tokens")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        Some(steamguard::SteamGuardAccount {
            account_name: name.clone(),
            steam_id: numeric_steam_id,
            serial_number: json_string(&json, "serial_number"),
            revocation_code: json_string(&json, "revocation_code").into(),
            shared_secret: steamguard::token::TwoFactorSecret::parse_shared_secret(
                shared_secret.clone(),
            )
            .map_err(|error| format!("{}: {error}", path.display()))?,
            token_gid: json_string(&json, "token_gid"),
            identity_secret: identity_secret.into(),
            uri: json_string(&json, "uri").into(),
            device_id,
            secret_1: json_string(&json, "secret_1").into(),
            tokens,
        })
    } else {
        None
    };

    Ok(Account {
        name,
        steam_id,
        shared_secret,
        mobile,
    })
}

fn json_string(json: &serde_json::Value, key: &str) -> String {
    json.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn json_id(json: &serde_json::Value) -> Option<String> {
    json.get("SteamID")
        .or_else(|| json.get("steamid"))
        .and_then(|value| match value {
            serde_json::Value::String(value) => Some(value.clone()),
            serde_json::Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
}

fn steam_device_id(steam_id: u64) -> String {
    let digest = Sha1::digest(steam_id.to_string().as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "android:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn steam_guard_code(shared_secret: &str, timestamp: u64) -> Result<String, String> {
    let secret = BASE64
        .decode(shared_secret)
        .map_err(|_| "Некорректный shared_secret".to_owned())?;
    let time_slice = (timestamp / 30).to_be_bytes();
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&secret)
        .map_err(|_| "Не удалось создать HMAC".to_owned())?;
    mac.update(&time_slice);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let mut value = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);

    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        code.push(STEAM_CHARS[(value % STEAM_CHARS.len() as u32) as usize] as char);
        value /= STEAM_CHARS.len() as u32;
    }
    Ok(code)
}

fn unix_time_precise() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn create_tray_icon() -> Result<tray_icon::TrayIcon, String> {
    let icon_data = eframe::icon_data::from_png_bytes(LOGO_BYTES)
        .map_err(|error| format!("Не удалось прочитать иконку трея: {error}"))?;
    let icon = tray_icon::Icon::from_rgba(icon_data.rgba, icon_data.width, icon_data.height)
        .map_err(|error| format!("Не удалось подготовить иконку трея: {error}"))?;

    tray_icon::TrayIconBuilder::new()
        .with_tooltip(APP_NAME)
        .with_icon(icon)
        .with_menu_on_left_click(false)
        .with_menu_on_right_click(false)
        .build()
        .map_err(|error| format!("Не удалось создать иконку в трее: {error}"))
}

fn restore_main_window(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
}

#[cfg(windows)]
fn wake_main_window_native() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SW_SHOWNOACTIVATE, ShowWindow};

    let title = APP_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: `title` is a valid, null-terminated UTF-16 string for the
    // duration of both Win32 calls. The returned handle is checked first.
    unsafe {
        let window = FindWindowW(std::ptr::null(), title.as_ptr());
        if !window.is_null() {
            ShowWindow(window, SW_SHOWNOACTIVATE);
        }
    }
}

#[cfg(not(windows))]
fn wake_main_window_native() {}

#[cfg(windows)]
fn tray_pointer_action(previous_buttons: &std::sync::atomic::AtomicU8) -> TrayPointerAction {
    use windows_sys::Win32::{
        Foundation::{POINT, RECT},
        UI::{
            Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON, VK_RBUTTON},
            WindowsAndMessaging::{FindWindowW, GetCursorPos, GetWindowRect},
        },
    };

    // SAFETY: all pointers refer to initialized local Win32 structures.
    let (current_buttons, pressed_since_last_poll, window, cursor, rect) = unsafe {
        let left_state = GetAsyncKeyState(VK_LBUTTON as i32);
        let right_state = GetAsyncKeyState(VK_RBUTTON as i32);
        let left_down = left_state < 0;
        let right_down = right_state < 0;
        let current_buttons = u8::from(left_down) | (u8::from(right_down) << 1);
        let pressed_since_last_poll =
            u8::from(left_state & 1 != 0) | (u8::from(right_state & 1 != 0) << 1);
        let mut cursor = POINT::default();
        let mut rect = RECT::default();
        let title = TRAY_POPUP_TITLE
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let window = FindWindowW(std::ptr::null(), title.as_ptr());
        if window.is_null()
            || GetCursorPos(&mut cursor) == 0
            || GetWindowRect(window, &mut rect) == 0
        {
            return TrayPointerAction::None;
        }
        (
            current_buttons,
            pressed_since_last_poll,
            window,
            cursor,
            rect,
        )
    };
    let _ = window;
    let old_buttons = previous_buttons.swap(current_buttons, std::sync::atomic::Ordering::Relaxed);
    let newly_pressed = pressed_since_last_poll | (current_buttons & !old_buttons);
    if newly_pressed == 0 {
        return TrayPointerAction::None;
    }

    let inside = cursor.x >= rect.left
        && cursor.x < rect.right
        && cursor.y >= rect.top
        && cursor.y < rect.bottom;
    if !inside {
        return TrayPointerAction::Close;
    }

    if newly_pressed & 1 != 0 {
        let scale = (rect.right - rect.left) as f32 / TRAY_POPUP_WIDTH;
        let footer_top = rect.bottom - (62.0 * scale).round() as i32;
        if cursor.y >= footer_top {
            return TrayPointerAction::Exit;
        }
    }
    TrayPointerAction::None
}

#[cfg(not(windows))]
fn tray_pointer_action(_previous_buttons: &std::sync::atomic::AtomicU8) -> TrayPointerAction {
    TrayPointerAction::None
}

fn tray_popup_height(screen: Screen, account_count: usize) -> f32 {
    if screen != Screen::Ready {
        280.0
    } else if account_count == 0 {
        225.0
    } else {
        150.0 + TRAY_ACCOUNT_HEIGHT * account_count.min(6) as f32
    }
}

fn shortened_login(login: &str) -> String {
    const MAX_CHARS: usize = 20;
    if login.chars().count() <= MAX_CHARS {
        login.to_owned()
    } else {
        format!("{}…", login.chars().take(MAX_CHARS - 1).collect::<String>())
    }
}

fn tray_account_row(ui: &mut egui::Ui, login: &str, code: &str) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), TRAY_ACCOUNT_HEIGHT - 4.0),
        egui::Sense::click(),
    );
    let fill = if response.hovered() {
        accent_soft()
    } else {
        elevated()
    };
    let stroke = if response.hovered() {
        Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(181, 154, 255, 90))
    } else {
        Stroke::new(1.0_f32, border())
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(10),
        fill,
        stroke,
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        shortened_login(login),
        egui::FontId::proportional(12.0),
        if response.hovered() {
            Color32::WHITE
        } else {
            muted()
        },
    );
    ui.painter().text(
        egui::pos2(rect.right() - 12.0, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        code,
        egui::FontId::monospace(17.0),
        if code == "-----" { danger() } else { accent() },
    );
    response.on_hover_text("Скопировать код")
}

fn tray_exit_button(ui: &mut egui::Ui) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 40.0), egui::Sense::click());
    if response.hovered() {
        ui.painter().rect_filled(
            rect,
            CornerRadius::same(10),
            Color32::from_rgba_unmultiplied(248, 113, 132, 18),
        );
    }
    ui.painter().text(
        egui::pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        "Закрыть приложение",
        egui::FontId::proportional(13.0),
        if response.hovered() {
            danger()
        } else {
            muted()
        },
    );
    ui.painter().text(
        egui::pos2(rect.right() - 12.0, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        "ВЫХОД",
        egui::FontId::proportional(9.0),
        subtle(),
    );
    response
}

fn load_logo(ctx: &egui::Context) -> egui::TextureHandle {
    let icon = eframe::icon_data::from_png_bytes(LOGO_BYTES)
        .expect("embedded logo.png must be a valid PNG");
    let image = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    ctx.load_texture("steam_vault_logo", image, egui::TextureOptions::LINEAR)
}

fn title_bar(ctx: &egui::Context, logo_texture: &egui::TextureHandle) {
    const HEIGHT: f32 = 40.0;
    const BUTTON_WIDTH: f32 = 46.0;

    egui::TopBottomPanel::top("window_title_bar")
        .exact_height(HEIGHT)
        .frame(egui::Frame::new().fill(sidebar()))
        .show(ctx, |ui| {
            let rect = ui.max_rect();
            let painter = ui.painter();

            painter.line_segment(
                [rect.left_bottom(), rect.right_bottom()],
                Stroke::new(1.0_f32, border()),
            );

            let logo = egui::Rect::from_center_size(
                egui::pos2(rect.left() + 22.0, rect.center().y),
                Vec2::splat(22.0),
            );
            painter.image(
                logo_texture.id(),
                logo,
                egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                Color32::WHITE,
            );
            painter.text(
                egui::pos2(42.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                APP_NAME,
                egui::FontId::proportional(12.0),
                Color32::from_rgb(228, 218, 239),
            );

            let close_rect = egui::Rect::from_min_max(
                egui::pos2(rect.right() - BUTTON_WIDTH, rect.top()),
                rect.right_bottom(),
            );
            let minimize_rect = close_rect.translate(Vec2::new(-BUTTON_WIDTH, 0.0));

            if title_bar_button(ui, close_rect, "×", true).clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if title_bar_button(ui, minimize_rect, "—", false).clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }

            let drag_rect = egui::Rect::from_min_max(
                rect.left_top(),
                egui::pos2(minimize_rect.left(), rect.bottom()),
            );
            let drag = ui.interact(
                drag_rect,
                egui::Id::new("window_drag_area"),
                egui::Sense::click_and_drag(),
            );
            if drag.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
        });
}

fn title_bar_button(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    symbol: &str,
    close: bool,
) -> egui::Response {
    let response = ui.interact(
        rect,
        egui::Id::new(("title_bar_button", symbol)),
        egui::Sense::click(),
    );
    if response.hovered() {
        let fill = if close {
            Color32::from_rgb(196, 43, 55)
        } else {
            Color32::from_rgb(47, 35, 61)
        };
        ui.painter().rect_filled(rect, CornerRadius::ZERO, fill);
    }
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        symbol,
        egui::FontId::proportional(if symbol == "×" { 19.0 } else { 14.0 }),
        Color32::from_rgb(232, 224, 241),
    );
    response
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = background();
    visuals.window_fill = card();
    visuals.override_text_color = Some(Color32::from_rgb(238, 241, 248));
    visuals.faint_bg_color = elevated();
    visuals.extreme_bg_color = Color32::from_rgb(5, 7, 12);
    visuals.window_stroke = Stroke::new(1.0_f32, border());
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(24, 28, 41);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(19, 22, 33);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, border());
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(36, 39, 58);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(31, 34, 50);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, accent());
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5_f32, Color32::WHITE);
    visuals.widgets.active.bg_fill = Color32::from_rgb(79, 66, 124);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(199, 181, 255));
    visuals.selection.bg_fill = Color32::from_rgb(77, 64, 122);
    visuals.selection.stroke = Stroke::new(1.0_f32, Color32::from_rgb(213, 200, 255));
    visuals.hyperlink_color = accent();
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 10.0);
    style.spacing.button_padding = Vec2::new(15.0, 9.0);
    style.spacing.interact_size.y = 38.0;
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(10);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(10);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(10);
    ctx.set_style(style);
}

fn auth_background(ctx: &egui::Context) {
    egui::CentralPanel::default()
        .frame(egui::Frame::new().fill(background()))
        .show(ctx, |ui| {
            let rect = ui.max_rect();
            let painter = ui.painter();
            painter.circle_filled(
                egui::pos2(rect.left() + 70.0, rect.top() + 20.0),
                240.0,
                Color32::from_rgba_unmultiplied(130, 105, 225, 18),
            );
            painter.circle_filled(
                egui::pos2(rect.right() - 10.0, rect.bottom() + 70.0),
                290.0,
                Color32::from_rgba_unmultiplied(72, 168, 214, 10),
            );
        });
}

fn auth_card(ui: &mut egui::Ui, width: f32, content: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(card())
        .stroke(Stroke::new(1.0_f32, border()))
        .corner_radius(CornerRadius::same(20))
        .inner_margin(egui::Margin::same(34))
        .shadow(egui::epaint::Shadow {
            offset: [0, 16],
            blur: 40,
            spread: 0,
            color: Color32::from_black_alpha(110),
        })
        .show(ui, |ui| {
            ui.set_width(width);
            content(ui);
        });
}

fn modal_backdrop(ctx: &egui::Context, id: &str) {
    let screen = ctx.screen_rect();
    egui::Area::new(egui::Id::new(id))
        // Keep the backdrop below the modal card even after it receives a click.
        // Areas in the same layer can otherwise be raised above one another.
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            let (rect, _) = ui.allocate_exact_size(screen.size(), egui::Sense::click());
            ui.painter()
                .rect_filled(rect, CornerRadius::ZERO, Color32::from_black_alpha(175));
        });
}

fn modal_card(ui: &mut egui::Ui, width: f32, content: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(16, 19, 29))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(54, 60, 79)))
        .corner_radius(CornerRadius::same(20))
        .inner_margin(egui::Margin::same(26))
        .shadow(egui::epaint::Shadow {
            offset: [0, 18],
            blur: 48,
            spread: 2,
            color: Color32::from_black_alpha(150),
        })
        .show(ui, |ui| {
            ui.set_width(width);
            content(ui);
        });
}

fn modal_header(ui: &mut egui::Ui, eyebrow: &str, title: &str, subtitle: &str) -> bool {
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 68.0), egui::Sense::hover());
    let painter = ui.painter();
    painter.text(
        rect.left_top(),
        egui::Align2::LEFT_TOP,
        eyebrow,
        egui::FontId::proportional(9.0),
        accent(),
    );
    painter.text(
        egui::pos2(rect.left(), rect.top() + 21.0),
        egui::Align2::LEFT_TOP,
        title,
        egui::FontId::proportional(23.0),
        Color32::WHITE,
    );
    painter.text(
        egui::pos2(rect.left(), rect.top() + 52.0),
        egui::Align2::LEFT_TOP,
        subtitle,
        egui::FontId::proportional(11.0),
        muted(),
    );

    let close_rect = egui::Rect::from_center_size(
        egui::pos2(rect.right() - 15.0, rect.top() + 15.0),
        Vec2::splat(30.0),
    );
    let close = ui.interact(
        close_rect,
        ui.id().with("modal_close"),
        egui::Sense::click(),
    );
    if close.hovered() {
        painter.rect_filled(close_rect, CornerRadius::same(8), elevated());
    }
    painter.text(
        close_rect.center(),
        egui::Align2::CENTER_CENTER,
        "×",
        egui::FontId::proportional(19.0),
        if close.hovered() {
            Color32::WHITE
        } else {
            subtle()
        },
    );
    close.clicked()
}

fn modal_status(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    egui::Frame::new()
        .fill(elevated())
        .stroke(Stroke::new(1.0_f32, border()))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(egui::Margin::symmetric(18, 26))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.add_space(10.0);
                ui.label(RichText::new(title).size(15.0).strong());
                ui.label(RichText::new(subtitle).size(11.0).color(muted()));
            });
        });
}

fn auth_kicker(ui: &mut egui::Ui, text: &str) {
    ui.vertical_centered(|ui| {
        egui::Frame::new()
            .fill(accent_soft())
            .stroke(Stroke::new(
                1.0_f32,
                Color32::from_rgba_unmultiplied(181, 154, 255, 70),
            ))
            .corner_radius(CornerRadius::same(20))
            .inner_margin(egui::Margin::symmetric(12, 5))
            .show(ui, |ui| {
                ui.label(RichText::new(text).size(9.0).strong().color(accent()));
            });
    });
}

fn sidebar_identity(ui: &mut egui::Ui, account_count: usize) {
    ui.label(RichText::new("MORTY STEAM AUTH").size(16.0).strong());
    ui.add_space(3.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("PERSONAL SECURITY")
                .size(9.0)
                .strong()
                .color(accent()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{account_count:02}"))
                    .monospace()
                    .size(10.0)
                    .color(subtle()),
            );
        });
    });
}

fn nav_button(
    ui: &mut egui::Ui,
    selected: bool,
    number: &str,
    label: &str,
    count: Option<usize>,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 42.0), egui::Sense::click());
    let fill = if selected {
        accent_soft()
    } else if response.hovered() {
        elevated()
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, CornerRadius::same(10), fill);
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(rect.left(), rect.top() + 9.0),
                egui::pos2(rect.left() + 2.0, rect.bottom() - 9.0),
            ),
            CornerRadius::same(2),
            accent(),
        );
    }
    ui.painter().text(
        egui::pos2(rect.left() + 14.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        number,
        egui::FontId::monospace(9.0),
        if selected { accent() } else { subtle() },
    );
    ui.painter().text(
        egui::pos2(rect.left() + 44.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.0),
        if selected { Color32::WHITE } else { muted() },
    );
    if let Some(count) = count {
        ui.painter().text(
            egui::pos2(rect.right() - 12.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            count.to_string(),
            egui::FontId::monospace(10.0),
            if count > 0 { accent() } else { subtle() },
        );
    }
    response
}

fn local_security_badge(ui: &mut egui::Ui) {
    egui::Frame::new()
        .fill(Color32::from_rgba_unmultiplied(76, 214, 160, 10))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(76, 214, 160, 45),
        ))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(11, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (dot, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
                ui.painter().circle_filled(dot.center(), 3.5, success());
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("ЗАЩИЩЕНО")
                            .size(9.0)
                            .strong()
                            .color(success()),
                    );
                    ui.label(
                        RichText::new("AES-256 · локально")
                            .size(10.0)
                            .color(subtle()),
                    );
                });
            });
        });
}

fn smooth_progress_bar(ui: &mut egui::Ui, progress: f32, width: f32) {
    let progress = progress.clamp(0.0, 1.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 6.0), egui::Sense::hover());
    let radius = CornerRadius::same(3);
    ui.painter().rect_filled(rect, radius, elevated());

    let filled_width = rect.width() * progress;
    if filled_width > 0.5 {
        let filled = egui::Rect::from_min_max(
            rect.min,
            egui::pos2(
                (rect.left() + filled_width).min(rect.right()),
                rect.bottom(),
            ),
        );
        ui.painter().rect_filled(filled, radius, accent());
        ui.painter().circle_filled(
            egui::pos2(filled.right(), filled.center().y),
            3.0,
            Color32::from_rgb(218, 205, 255),
        );
    }
}

fn paint_ambient(ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    ui.painter().circle_filled(
        egui::pos2(rect.right() + 70.0, rect.top() - 35.0),
        190.0,
        Color32::from_rgba_unmultiplied(133, 105, 220, 9),
    );
}

fn auth_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.vertical_centered(|ui| {
        ui.heading(RichText::new(title).size(28.0).strong());
        ui.add_space(6.0);
        ui.label(RichText::new(subtitle).size(14.0).color(muted()));
    });
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).strong().color(muted()));
    ui.add_space(3.0);
}

fn primary_button(text: &'static str) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text)
            .strong()
            .color(Color32::from_rgb(17, 15, 26)),
    )
    .fill(accent())
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(10))
}

fn security_note(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new()
        .fill(elevated())
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("●").size(8.0).color(success()));
                ui.label(RichText::new(text).size(11.0).color(muted()));
            });
        });
}

fn empty_state(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        let (icon, _) = ui.allocate_exact_size(Vec2::splat(52.0), egui::Sense::hover());
        ui.painter().rect_stroke(
            icon,
            CornerRadius::same(14),
            Stroke::new(1.0_f32, border()),
            egui::StrokeKind::Inside,
        );
        ui.painter().text(
            icon.center(),
            egui::Align2::CENTER_CENTER,
            "+",
            egui::FontId::proportional(24.0),
            accent(),
        );
        ui.add_space(16.0);
        ui.heading(
            RichText::new("Здесь появятся ваши коды")
                .size(22.0)
                .strong(),
        );
        ui.label(
            RichText::new("Добавьте maFile или перетащите файлы в окно")
                .size(13.0)
                .color(muted()),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("Все данные остаются на вашем компьютере")
                .small()
                .color(success()),
        );
    });
}

fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str, busy: bool) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.heading(RichText::new(title).size(26.0).strong());
            ui.add_space(3.0);
            ui.label(RichText::new(subtitle).size(13.0).color(muted()));
        });
        if busy {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spinner();
            });
        }
    });
    ui.add_space(12.0);
}

fn info_empty(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    egui::Frame::new()
        .fill(card())
        .stroke(Stroke::new(1.0_f32, border()))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(20))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).size(17.0).strong());
            ui.label(RichText::new(subtitle).color(muted()));
        });
    ui.add_space(10.0);
}

fn background() -> Color32 {
    Color32::from_rgb(8, 10, 16)
}

fn sidebar() -> Color32 {
    Color32::from_rgb(11, 13, 21)
}

fn card() -> Color32 {
    Color32::from_rgb(17, 20, 30)
}

fn elevated() -> Color32 {
    Color32::from_rgb(23, 27, 40)
}

fn border() -> Color32 {
    Color32::from_rgb(43, 49, 65)
}

fn accent() -> Color32 {
    Color32::from_rgb(181, 154, 255)
}

fn accent_soft() -> Color32 {
    Color32::from_rgb(34, 31, 55)
}

fn muted() -> Color32 {
    Color32::from_rgb(169, 176, 195)
}

fn subtle() -> Color32 {
    Color32::from_rgb(106, 116, 139)
}

fn success() -> Color32 {
    Color32::from_rgb(76, 214, 160)
}

fn danger() -> Color32 {
    Color32::from_rgb(248, 113, 132)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_confirmation_rows() -> Vec<ConfirmationRow> {
        (0..80)
            .map(|index| ConfirmationRow {
                account_index: 0,
                id: (index + 1).to_string(),
                nonce: (index + 100).to_string(),
                load_id: 1,
                kind: if index < 48 {
                    "Трейд"
                } else if index < 76 {
                    "Продажа"
                } else {
                    "Steam Family"
                }
                .to_owned(),
                headline: "Подтверждение действия с аккаунтом Steam".to_owned(),
                summary: "Описание ожидающего подтверждения".to_owned(),
                created: 0,
                icon: None,
                is_trade: index < 48,
                is_market_sale: (48..76).contains(&index),
                trade: (index < 48).then(|| {
                    Ok(steam_trade::TradeDetails {
                        giving: vec![
                            steam_trade::TradeItem {
                                name: "Предмет обмена".to_owned(),
                                game: "Counter-Strike 2".to_owned(),
                                app_id: 730,
                                image: None,
                                amount: 1
                            };
                            if index == 5 { 100 } else { 1 }
                        ],
                        ..Default::default()
                    })
                }),
            })
            .collect()
    }

    #[test]
    fn confirmation_list_fills_main_page_height_with_compact_collapsed_cards() {
        let context = egui::Context::default();
        configure_style(&context);
        let rows = test_confirmation_rows();
        for _ in 0..2 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(980.0, 680.0),
                )),
                ..Default::default()
            };
            let _ = context.run(input, |ctx| {
                egui::SidePanel::left("navigation")
                    .exact_width(228.0)
                    .show(ctx, |_| {});
                egui::CentralPanel::default()
                    .frame(egui::Frame::new().inner_margin(egui::Margin::same(28)))
                    .show(ctx, |ui| {
                        section_header(
                            ui,
                            "Подтверждения · 80",
                            "Обмены, торговая площадка, Steam Family и действия с аккаунтом",
                            false,
                        );
                        ui.horizontal(|ui| {
                            let _ = ui.button("Обновить");
                            let _ = ui.button("Действия со списком");
                            let _ = ui.button("Предметы");
                        });
                        ui.add_space(10.0);
                        let available = ui.available_height();
                        let output = confirmation_list_ui(ui, &rows, &[], true, Some(false));
                        assert!(
                            output.inner_rect.height() > 400.0,
                            "scroll area too short: {:?}",
                            output.inner_rect
                        );
                        assert!((output.inner_rect.height() - available).abs() < 2.0);
                        assert!(output.content_size.y > output.inner_rect.height() * 8.0);
                        assert!(
                            output.content_size.y < 11000.0,
                            "collapsed cards too tall: {:?}",
                            output.content_size
                        );
                    });
            });
        }
    }

    #[test]
    fn confirmation_card_uses_full_width_and_only_expands_for_items() {
        let context = egui::Context::default();
        configure_style(&context);
        context.style_mut(|style| style.animation_time = 0.0);
        let row = test_confirmation_rows().remove(5);
        let mut heights = Vec::new();
        for open in [false, true, false] {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(700.0, 900.0),
                )),
                ..Default::default()
            };
            let _ = context.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let width = ui.available_width();
                    let output = confirmation_card_ui(ui, &row, "Аккаунт", true, Some(open));
                    assert!((output.response.rect.width() - width).abs() < 2.0);
                    let [accept, reject] = output.inner.action_rects;
                    assert!(
                        (accept.top() - reject.top()).abs() < 1.0,
                        "buttons are misaligned: {accept:?}, {reject:?}"
                    );
                    assert_eq!(accept.size(), reject.size());
                    assert!(accept.right() < reject.left());
                    assert!(
                        output.response.rect.contains_rect(accept)
                            && output.response.rect.contains_rect(reject),
                        "buttons outside card: {:?}, {accept:?}, {reject:?}",
                        output.response.rect
                    );
                    heights.push(output.response.rect.height());
                });
            });
        }
        assert!(heights[0] < 125.0, "collapsed card too tall: {heights:?}");
        assert!(
            heights[1] > heights[0] * 4.0,
            "items did not expand: {heights:?}"
        );
        assert!(
            heights[2] < 125.0,
            "card did not shrink after closing: {heights:?}"
        );
    }

    #[test]
    fn bulk_selection_distinguishes_sales_trades_and_other_actions() {
        let rows = test_confirmation_rows();
        assert_eq!(
            rows.iter()
                .filter(|row| ConfirmationScope::All.matches(row))
                .count(),
            80
        );
        assert_eq!(
            rows.iter()
                .filter(|row| ConfirmationScope::Trades.matches(row))
                .count(),
            48
        );
        assert_eq!(
            rows.iter()
                .filter(|row| ConfirmationScope::Sales.matches(row))
                .count(),
            28
        );
    }

    #[test]
    fn bulk_groups_preserve_accounts_and_reject_missing_accounts() {
        let account = |name: &str| Account {
            name: name.to_owned(),
            steam_id: None,
            shared_secret: String::new(),
            mobile: Some(steamguard::SteamGuardAccount {
                account_name: name.to_owned(),
                ..Default::default()
            }),
        };
        let accounts = vec![account("one"), account("two")];
        let mut rows: Vec<_> = test_confirmation_rows().into_iter().take(3).collect();
        for (index, row) in rows.iter_mut().enumerate() {
            row.id = (index + 1).to_string();
            row.nonce = (index + 10).to_string();
            row.account_index = index % 2;
        }
        let groups = prepare_confirmation_groups(&accounts, &rows).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].account.account_name, "one");
        assert_eq!(
            groups[0]
                .targets
                .iter()
                .map(|target| target.id.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "3"]
        );
        assert_eq!(groups[1].targets[0].nonce, "11");
        rows[0].account_index = 2;
        assert!(prepare_confirmation_groups(&accounts, &rows).is_err());
    }

    #[test]
    fn trade_items_wrap_long_names_in_narrow_columns() {
        let context = egui::Context::default();
        let item = steam_trade::TradeItem {
            name:
                "Очень длинное название предмета обмена со всеми дополнительными характеристиками"
                    .to_owned(),
            game: "Counter-Strike 2".to_owned(),
            app_id: 730,
            image: None,
            amount: 2,
        };
        for width in [260.0, 480.0] {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(width, 900.0),
                )),
                ..Default::default()
            };
            let _ = context.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let available = ui.available_width();
                    trade_items_ui(ui, "Вы отдаёте", std::slice::from_ref(&item));
                    assert!(
                        ui.min_rect().width() <= available + 1.0,
                        "trade item overflow: {} > {available}",
                        ui.min_rect().width()
                    );
                });
            });
        }
    }

    #[test]
    fn generated_code_has_steam_format() {
        let secret = BASE64.encode(b"test shared secret");
        let code = steam_guard_code(&secret, 1_700_000_000).unwrap();
        assert_eq!(code.len(), 5);
        assert!(
            code.bytes()
                .all(|character| STEAM_CHARS.contains(&character))
        );
    }

    #[test]
    fn vault_round_trip() {
        let path =
            std::env::temp_dir().join(format!("morty-auth-test-{}.json", std::process::id()));
        let salt = [7_u8; 16];
        let key = derive_key("correct horse battery staple", &salt).unwrap();
        let data = VaultData {
            accounts: vec![Account {
                name: "test".to_owned(),
                steam_id: Some("76561198000000000".to_owned()),
                shared_secret: BASE64.encode(b"secret"),
                mobile: None,
            }],
        };
        save_vault(&path, &data, &key, &salt).unwrap();
        save_vault(&path, &data, &key, &salt).unwrap();
        let (loaded, _, _) = load_vault(&path, "correct horse battery staple").unwrap();
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].name, "test");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn imports_sda_session_steam_id_and_generates_device_id() {
        let path =
            std::env::temp_dir().join(format!("76561198000000001-{}.maFile", std::process::id()));
        let data = serde_json::json!({
            "account_name": "sda_test",
            "shared_secret": BASE64.encode([1_u8; 20]),
            "identity_secret": BASE64.encode([2_u8; 20]),
            "device_id": "",
            "Session": { "SteamID": "76561198000000001" }
        });
        fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();

        let account = parse_mafile(&path).unwrap();
        let mobile = account.mobile.expect("full SDA maFile must support login");
        assert_eq!(mobile.steam_id, 76561198000000001);
        assert!(mobile.device_id.starts_with("android:"));

        let _ = fs::remove_file(path);
    }
}
