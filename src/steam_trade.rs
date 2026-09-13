use std::{collections::HashMap, sync::OnceLock, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use regex::Regex;
use reqwest::{
    blocking::{Client, Response},
    header,
};
use scraper::{Html, Selector};
use serde_json::Value;
use sha1::Sha1;
use steamguard::{ExposeSecret, SteamGuardAccount};

#[derive(Clone, Debug)]
pub(crate) struct TradeItem {
    pub name: String,
    pub game: String,
    pub app_id: u64,
    pub image: Option<String>,
    pub amount: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TradeDetails {
    pub giving: Vec<TradeItem>,
    pub receiving: Vec<TradeItem>,
    pub partner_id: Option<String>,
    pub avatar: Option<String>,
}

pub(crate) fn community_client(account: &SteamGuardAccount) -> Result<Client, String> {
    let tokens = account.tokens.as_ref().ok_or("Нужна авторизация Steam")?;
    let mut headers = header::HeaderMap::new();
    let cookie = format!(
        "steamLoginSecure={}%7C%7C{}; steamid={}",
        account.steam_id,
        tokens.access_token().expose_secret(),
        account.steam_id
    );
    let mut value =
        header::HeaderValue::from_str(&cookie).map_err(|_| "Некорректная сессия Steam")?;
    value.set_sensitive(true);
    headers.insert(header::COOKIE, value);
    headers.insert(
        header::ACCEPT_LANGUAGE,
        header::HeaderValue::from_static("en-US,en;q=0.9"),
    );
    Client::builder()
        .default_headers(headers)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        // Never forward the authenticated cookie through a redirect.
        .redirect(reqwest::redirect::Policy::none())
        .build().map_err(|e| format!("Не удалось создать клиент Steam: {e}"))
}

pub(crate) fn confirmation_params(
    account: &SteamGuardAccount,
    time: u64,
    tag: &str,
) -> Result<Vec<(&'static str, String)>, String> {
    let secret = BASE64
        .decode(account.identity_secret.expose_secret())
        .map_err(|_| "Некорректный identity_secret в maFile")?;
    if secret.is_empty() || account.device_id.is_empty() {
        return Err("В maFile не хватает данных для подтверждений".to_owned());
    }
    let mut mac =
        Hmac::<Sha1>::new_from_slice(&secret).map_err(|_| "Некорректный секрет подтверждений")?;
    mac.update(&time.to_be_bytes());
    mac.update(&tag.as_bytes()[..tag.len().min(32)]);
    Ok(vec![
        ("p", account.device_id.clone()),
        ("a", account.steam_id.to_string()),
        ("k", BASE64.encode(mac.finalize().into_bytes())),
        ("t", time.to_string()),
        ("m", "react".to_owned()),
        ("tag", tag.to_owned()),
    ])
}

pub(crate) fn response_params(
    account: &SteamGuardAccount,
    time: u64,
    id: &str,
    nonce: &str,
    accept: bool,
) -> Result<Vec<(&'static str, String)>, String> {
    let (operation, tag) = if accept {
        ("allow", "accept")
    } else {
        ("cancel", "reject")
    };
    let mut params = confirmation_params(account, time, tag)?;
    params.extend([
        ("op", operation.to_owned()),
        ("cid", id.to_owned()),
        ("ck", nonce.to_owned()),
    ]);
    Ok(params)
}

pub(crate) fn batch_response_params(
    account: &SteamGuardAccount,
    time: u64,
    targets: &[crate::steam::ConfirmationTarget],
    accept: bool,
) -> Result<Vec<(&'static str, String)>, String> {
    let (operation, tag) = if accept {
        ("allow", "accept")
    } else {
        ("cancel", "reject")
    };
    let mut params = confirmation_params(account, time, tag)?;
    params.push(("op", operation.to_owned()));
    for target in targets {
        params.push(("cid[]", target.id.clone()));
        params.push(("ck[]", target.nonce.clone()));
    }
    Ok(params)
}

pub(crate) fn read_mobile_response(response: Response) -> Result<Value, String> {
    read_mobile_response_checked(response).map_err(|error| error.message)
}

#[derive(Debug)]
pub(crate) struct MobileResponseError {
    pub message: String,
    pub retryable: bool,
}

impl MobileResponseError {
    fn new(message: impl Into<String>, retryable: bool) -> Self {
        Self {
            message: message.into(),
            retryable,
        }
    }
}

fn read_mobile_response_checked(response: Response) -> Result<Value, MobileResponseError> {
    let status = response.status();
    // Classify HTTP errors before reading or attempting to deserialize the body.
    check_mobile_status(status)?;
    let text = response.text().map_err(|error| {
        MobileResponseError::new(
            format!("Не удалось прочитать ответ Steam: {}", error.without_url()),
            true,
        )
    })?;
    parse_mobile_body(&text)
}

fn check_mobile_status(status: reqwest::StatusCode) -> Result<(), MobileResponseError> {
    if status.is_redirection() || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(MobileResponseError::new(
            "Сессия Steam истекла. Выполните авторизацию Steam заново",
            false,
        ));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(MobileResponseError::new(
            "Steam ограничил частоту запросов (HTTP 429). Подождите и обновите подтверждения",
            false,
        ));
    }
    if !status.is_success() {
        return Err(MobileResponseError::new(
            format!(
                "Steam не принял запрос (HTTP {}). Попробуйте обновить подтверждения позже",
                status.as_u16()
            ),
            status.is_server_error() || status == reqwest::StatusCode::REQUEST_TIMEOUT,
        ));
    }
    Ok(())
}

fn parse_mobile_body(text: &str) -> Result<Value, MobileResponseError> {
    if text.trim().is_empty() {
        return Err(MobileResponseError::new(
            "Steam вернул пустой ответ. Попробуйте обновить подтверждения позже",
            true,
        ));
    }
    let body: Value = serde_json::from_str(text).map_err(|_| MobileResponseError::new(
        "Steam вернул ответ в неожиданном формате вместо JSON. Попробуйте позже; если ошибка повторяется, проверьте VPN или прокси", true,
    ))?;
    validate_mobile_response(body).map_err(|message| MobileResponseError::new(message, false))
}

pub(crate) fn get_confirmations(
    client: &Client,
    account: &SteamGuardAccount,
    time: u64,
) -> Result<Vec<steamguard::Confirmation>, MobileResponseError> {
    let params = confirmation_params(account, time, "conf")
        .map_err(|message| MobileResponseError::new(message, false))?;
    let response = client
        .get("https://steamcommunity.com/mobileconf/getlist")
        .query(&params)
        .send()
        .map_err(|error| {
            let retryable = error.is_timeout() || error.is_connect() || error.is_body();
            MobileResponseError::new(
                format!(
                    "Не удалось загрузить подтверждения Steam: {}",
                    error.without_url()
                ),
                retryable,
            )
        })?;
    let body = read_mobile_response_checked(response)?;
    // Steam omits conf when the list is empty.
    let confirmations = body
        .get("conf")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    serde_json::from_value(confirmations).map_err(|_| MobileResponseError::new(
        "Steam вернул неподдерживаемый формат списка подтверждений. Попробуйте обновить подтверждения позже", false,
    ))
}

fn validate_mobile_response(body: Value) -> Result<Value, String> {
    if body["needauth"].as_bool() == Some(true) || body["needsauth"].as_bool() == Some(true) {
        return Err("Сессия Steam истекла. Выполните авторизацию Steam заново".to_owned());
    }
    if body["success"].as_bool() != Some(true) {
        let message = body["message"].as_str().or(body["detail"].as_str()).filter(|s| !s.is_empty())
            .unwrap_or("Steam не выполнил действие. Обновите список: подтверждение могло быть обработано или отменено на другом устройстве");
        return Err(message.to_owned());
    }
    Ok(body)
}

pub(crate) fn load_trade_details(
    account: &SteamGuardAccount,
    confirmation: &steamguard::Confirmation,
    games: &mut HashMap<u64, String>,
) -> Result<TradeDetails, String> {
    let client = community_client(account)?;
    let public = Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|e| e.to_string())?;
    // The mobile session token can read offers without asking the user for a Web API key.
    let token = account
        .tokens
        .as_ref()
        .ok_or("Нужна авторизация Steam")?
        .access_token()
        .expose_secret();
    let api = public
        .get("https://api.steampowered.com/IEconService/GetTradeOffer/v1/")
        .query(&[
            ("access_token", token),
            ("tradeofferid", confirmation.creator_id.as_str()),
            ("get_descriptions", "1"),
            ("language", "russian"),
        ])
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<Value>());
    let mut details = match api
        .ok()
        .and_then(|body| parse_api_offer(&body, &confirmation.creator_id).ok())
    {
        Some(details) => details,
        None => {
            // Support sessions which cannot use IEconService, using the same page as Steam's mobile app.
            let transport = steamguard::transport::WebApiTransport::new(public.clone());
            let time = steamguard::steamapi::get_server_time(transport)
                .map_err(|_| "Не удалось получить время Steam")?
                .server_time();
            let params = confirmation_params(account, time, "details")?;
            let response = client
                .get(format!(
                    "https://steamcommunity.com/mobileconf/detailspage/{}",
                    confirmation.id
                ))
                .query(&params)
                .send()
                .map_err(|e| format!("Не удалось загрузить состав обмена: {}", e.without_url()))?;
            let html = if response.status().is_success() {
                response
                    .text()
                    .map_err(|_| "Не удалось прочитать состав обмена")?
            } else {
                let response = client
                    .get(format!(
                        "https://steamcommunity.com/mobileconf/details/{}",
                        confirmation.id
                    ))
                    .query(&params)
                    .send()
                    .map_err(|e| {
                        format!("Не удалось загрузить состав обмена: {}", e.without_url())
                    })?;
                read_mobile_response(response)?["html"]
                    .as_str()
                    .ok_or("Steam не вернул состав обмена")?
                    .to_owned()
            };
            parse_trade_html(&html, &confirmation.creator_id)?
        }
    };
    details.avatar = confirmation
        .icon
        .as_deref()
        .and_then(steam_image_url)
        .or(details.avatar);
    if details.avatar.is_none()
        && let Some(id) = &details.partner_id
        && let Ok(id) = id.parse::<u64>()
        && let Some(account_id) = id.checked_sub(76561197960265728)
    {
        details.avatar = public
            .get(format!(
                "https://steamcommunity.com/miniprofile/{account_id}/json"
            ))
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<Value>())
            .ok()
            .and_then(|body| body["avatar_url"].as_str().and_then(steam_image_url));
    }
    for item in details
        .giving
        .iter_mut()
        .chain(details.receiving.iter_mut())
    {
        if item.game.is_empty() {
            item.game = games
                .entry(item.app_id)
                .or_insert_with(|| game_name(&public, item.app_id))
                .clone();
        }
    }
    Ok(details)
}

fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}
fn string_id(value: &Value) -> Option<String> {
    number(value).map(|v| v.to_string())
}

fn item_from_description(description: &Value, amount: u64) -> Result<TradeItem, String> {
    let inventory_app_id = number(&description["appid"]).ok_or("Steam не вернул игру предмета")?;
    // Steam cards/backgrounds use inventory 753 but belong to the game in market_fee_app.
    let app_id = if inventory_app_id == 753 {
        number(&description["market_fee_app"])
            .filter(|id| *id > 0)
            .unwrap_or(753)
    } else {
        inventory_app_id
    };
    let name = description["market_name"]
        .as_str()
        .or(description["name"].as_str())
        .filter(|s| !s.is_empty())
        .ok_or("Steam не вернул название предмета")?
        .to_owned();
    let image = description["icon_url_large"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or(description["icon_url"].as_str())
        .and_then(|icon| {
            if icon.starts_with("http") || icon.starts_with("//") {
                steam_image_url(icon)
            } else {
                steam_image_url(&format!(
                    "https://community.fastly.steamstatic.com/economy/image/{icon}/128fx128f"
                ))
            }
        });
    Ok(TradeItem {
        name,
        app_id,
        game: description["tags"]
            .as_array()
            .and_then(|tags| {
                tags.iter()
                    .find(|tag| tag["category"].as_str() == Some("Game"))
            })
            .and_then(|tag| tag["localized_tag_name"].as_str())
            .or_else(|| {
                if app_id == inventory_app_id {
                    description["app_name"].as_str()
                } else {
                    None
                }
            })
            .unwrap_or_default()
            .to_owned(),
        image,
        amount,
    })
}

fn parse_api_offer(body: &Value, expected_id: &str) -> Result<TradeDetails, String> {
    let offer = &body["response"]["offer"];
    if offer["tradeofferid"].as_str() != Some(expected_id) {
        return Err("Steam не вернул нужный обмен".to_owned());
    }
    let descriptions = body["response"]["descriptions"]
        .as_array()
        .ok_or("Нет описаний предметов")?;
    let mut details = TradeDetails::default();
    for (field, items) in [
        ("items_to_give", &mut details.giving),
        ("items_to_receive", &mut details.receiving),
    ] {
        if let Some(assets) = offer[field].as_array() {
            for asset in assets {
                let description = descriptions
                    .iter()
                    .find(|d| {
                        number(&d["appid"]) == number(&asset["appid"])
                            && string_id(&d["classid"]) == string_id(&asset["classid"])
                            && number(&d["instanceid"]).unwrap_or(0)
                                == number(&asset["instanceid"]).unwrap_or(0)
                    })
                    .ok_or("Steam пока не вернул описание всех предметов")?;
                items.push(item_from_description(
                    description,
                    number(&asset["amount"]).unwrap_or(1),
                )?);
            }
        }
    }
    if details.giving.is_empty() && details.receiving.is_empty() {
        return Err("Steam вернул пустой состав обмена".to_owned());
    }
    details.partner_id =
        number(&offer["accountid_other"]).map(|id| (76561197960265728 + id).to_string());
    Ok(details)
}

// Only public Steam CDN addresses are passed to the unauthenticated image loader.
pub(crate) fn steam_image_url(value: &str) -> Option<String> {
    let value = if value.starts_with("//") {
        format!("https:{value}")
    } else {
        value.to_owned()
    };
    let mut url = reqwest::Url::parse(&value).ok()?;
    let host = url.host_str()?;
    if ![
        "steamstatic.com",
        "steamusercontent.com",
        "steamcommunity.com",
        "akamaihd.net",
    ]
    .iter()
    .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    {
        return None;
    }
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_scheme("https").ok()?;
    Some(url.into())
}

fn selector(value: &str) -> Selector {
    Selector::parse(value).expect("static CSS selector")
}

fn parse_trade_html(html: &str, expected_id: &str) -> Result<TradeDetails, String> {
    let document = Html::parse_document(html);
    let offer = document
        .select(&selector(".tradeoffer"))
        .find(|e| {
            e.value().attr("id").is_some_and(|id| {
                id == format!("tradeoffer_{expected_id}")
                    || id == format!("tradeofferid_{expected_id}")
            })
        })
        .ok_or("Steam не вернул нужный обмен. Обновите подтверждения или авторизуйтесь заново")?;
    static HOVER: OnceLock<Regex> = OnceLock::new();
    let hover =
        HOVER.get_or_init(|| Regex::new(r#"BuildHover\s*\(\s*['"]([^'"]+)['"]\s*,\s*"#).unwrap());
    static ASSIGN: OnceLock<Regex> = OnceLock::new();
    let assign = ASSIGN.get_or_init(|| Regex::new(r"\boItem\s*=\s*\{").unwrap());
    let mut metadata = HashMap::new();
    for script in document.select(&selector("script")) {
        let script = script.inner_html();
        for call in hover.captures_iter(&script) {
            let start = call.get(0).unwrap();
            let rest = &script[start.end()..];
            let (description, consumed) = if rest.starts_with('{') {
                let mut stream = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
                let Some(Ok(value)) = stream.next() else {
                    continue;
                };
                (value, stream.byte_offset())
            } else if rest.starts_with("oItem") {
                let Some(position) = assign.find_iter(&script[..start.start()]).last() else {
                    continue;
                };
                let json = &script[position.end() - 1..start.start()];
                let Some(Ok(value)) = serde_json::Deserializer::from_str(json)
                    .into_iter::<Value>()
                    .next()
                else {
                    continue;
                };
                (value, 5)
            } else {
                continue;
            };
            let args = rest[consumed..].split(')').next().unwrap_or_default();
            let owner = args
                .trim_start()
                .trim_start_matches(',')
                .trim_start()
                .split(',')
                .next()
                .unwrap_or_default()
                .trim();
            let giving = match owner {
                "UserYou" => true,
                "UserThem" => false,
                _ => continue,
            };
            metadata.insert(call[1].to_owned(), (description, giving));
        }
    }
    let mut details = TradeDetails::default();
    for element in offer.select(&selector(".trade_item, .tradeoffer_item")) {
        let id = element
            .value()
            .attr("id")
            .ok_or("Steam не вернул ID предмета")?;
        let (description, giving) = metadata.get(id).ok_or(
            "Steam не вернул полное описание предметов. Нажмите «Обновить» и попробуйте снова",
        )?;
        let amount = element
            .select(&selector(".trade_item_amount, .item_amount"))
            .next()
            .and_then(|e| e.text().collect::<String>().trim().parse().ok())
            .or_else(|| number(&description["amount"]))
            .unwrap_or(1);
        let mut item = item_from_description(description, amount)?;
        if item.image.is_none() {
            item.image = element
                .select(&selector("img"))
                .next()
                .and_then(|e| e.value().attr("src"))
                .and_then(steam_image_url);
        }
        if *giving {
            details.giving.push(item);
        } else {
            details.receiving.push(item);
        }
    }
    if details.giving.is_empty() && details.receiving.is_empty() {
        return Err(
            "Steam пока не вернул состав обмена. Нажмите «Обновить» и попробуйте снова".to_owned(),
        );
    }
    details.avatar = offer
        .select(&selector(".tradeoffer_avatar img, .playerAvatar img"))
        .next()
        .and_then(|e| e.value().attr("src"))
        .and_then(steam_image_url);
    Ok(details)
}

fn game_name(client: &Client, app_id: u64) -> String {
    match app_id {
        730 => return "Counter-Strike 2".to_owned(),
        570 => return "Dota 2".to_owned(),
        440 => return "Team Fortress 2".to_owned(),
        753 => return "Steam".to_owned(),
        252490 => return "Rust".to_owned(),
        _ => {}
    }
    client
        .get("https://store.steampowered.com/api/appdetails")
        .query(&[
            ("appids", app_id.to_string()),
            ("filters", "basic".to_owned()),
            ("l", "russian".to_owned()),
        ])
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<Value>())
        .ok()
        .and_then(|body| {
            body[app_id.to_string()]["data"]["name"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("Игра Steam · App ID {app_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_http_errors_do_not_become_json_errors() {
        for status in [302, 401, 403, 429, 500, 502, 503] {
            let error =
                check_mobile_status(reqwest::StatusCode::from_u16(status).unwrap()).unwrap_err();
            assert_eq!(error.retryable, status >= 500);
            assert!(!error.message.contains("deserialize"));
            if status == 302 || status == 401 {
                assert!(error.message.contains("авторизацию"));
            } else {
                assert!(error.message.contains(&status.to_string()));
            }
        }
    }

    #[test]
    fn empty_or_non_json_mobile_responses_can_be_retried() {
        for body in [
            "",
            " \r\n",
            "<html>Service Unavailable</html>",
            "{\"success\":",
        ] {
            let error = parse_mobile_body(body).unwrap_err();
            assert!(error.retryable);
            assert!(!error.message.contains(body.trim()) || body.trim().is_empty());
        }
        assert!(
            parse_mobile_body(" ")
                .unwrap_err()
                .message
                .contains("пустой")
        );
    }

    #[test]
    fn expired_sessions_and_rejected_actions_are_not_retried() {
        for body in [
            r#"{"success":false,"needauth":true}"#,
            r#"{"success":true,"needsauth":true}"#,
            r#"{"success":false,"message":"Expired"}"#,
            r#"{"unexpected":true}"#,
            "null",
        ] {
            assert!(!parse_mobile_body(body).unwrap_err().retryable);
        }
        let body = parse_mobile_body(r#"{"success":true,"conf":[]}"#).unwrap();
        assert_eq!(body["conf"], serde_json::json!([]));
        assert!(parse_mobile_body(r#"{"success":true}"#).is_ok());
    }

    #[test]
    fn response_request_signs_accept_and_reject_and_encodes_hash() {
        let account = SteamGuardAccount {
            steam_id: 76561198000000001,
            device_id: "android:test".to_owned(),
            identity_secret: BASE64.encode((0_u8..20).collect::<Vec<_>>()).into(),
            ..Default::default()
        };
        // Reference HMAC-SHA1 vectors calculated independently with Python's hmac.
        for (accept, op, tag, hash) in [
            (true, "allow", "accept", "0bBIomcF2qVl/zF4isGPy7YSJTs="),
            (false, "cancel", "reject", "0E4Gy/o/DiuW/fzukIVNb6S6rAg="),
        ] {
            let params = response_params(&account, 1700000000, "123", "456", accept).unwrap();
            let request = Client::new()
                .get("https://steamcommunity.com/mobileconf/ajaxop")
                .query(&params)
                .build()
                .unwrap();
            let query: HashMap<_, _> = request.url().query_pairs().collect();
            assert_eq!(query["op"], op);
            assert_eq!(query["tag"], tag);
            assert_eq!(query["k"], hash);
            assert_eq!(query["cid"], "123");
            assert_eq!(query["ck"], "456");
        }
        assert!(confirmation_params(&SteamGuardAccount::default(), 1, "reject").is_err());
    }

    #[test]
    fn batch_request_preserves_confirmation_key_pairs_and_signature() {
        let account = SteamGuardAccount {
            device_id: "android:test".to_owned(),
            identity_secret: BASE64.encode((0_u8..20).collect::<Vec<_>>()).into(),
            ..Default::default()
        };
        let targets = vec![
            crate::steam::ConfirmationTarget {
                load_id: 1,
                id: "12".to_owned(),
                nonce: "34".to_owned(),
            },
            crate::steam::ConfirmationTarget {
                load_id: 1,
                id: "56".to_owned(),
                nonce: "78".to_owned(),
            },
        ];
        for (accept, tag, op, hash) in [
            (true, "accept", "allow", "0bBIomcF2qVl/zF4isGPy7YSJTs="),
            (false, "reject", "cancel", "0E4Gy/o/DiuW/fzukIVNb6S6rAg="),
        ] {
            let params = batch_response_params(&account, 1700000000, &targets, accept).unwrap();
            let request = Client::new()
                .post("https://steamcommunity.com/mobileconf/multiajaxop")
                .form(&params)
                .build()
                .unwrap();
            let bytes = request.body().unwrap().as_bytes().unwrap();
            let body = std::str::from_utf8(bytes).unwrap();
            let url = reqwest::Url::parse(&format!("https://example.invalid/?{body}")).unwrap();
            let pairs: Vec<_> = url.query_pairs().collect();
            assert_eq!(
                pairs
                    .iter()
                    .filter(|(key, _)| key == "cid[]")
                    .map(|(_, value)| value.as_ref())
                    .collect::<Vec<_>>(),
                vec!["12", "56"]
            );
            assert_eq!(
                pairs
                    .iter()
                    .filter(|(key, _)| key == "ck[]")
                    .map(|(_, value)| value.as_ref())
                    .collect::<Vec<_>>(),
                vec!["34", "78"]
            );
            let query: HashMap<_, _> = pairs.into_iter().collect();
            assert_eq!(query["tag"], tag);
            assert_eq!(query["op"], op);
            assert_eq!(query["k"], hash);
        }
    }

    #[test]
    fn api_preserves_sides_amounts_and_description_identity() {
        let body = serde_json::json!({"response": {"offer": {"tradeofferid":"42", "accountid_other":123,
            "items_to_give":[{"appid":730,"classid":"5","instanceid":"2","amount":"3"}],
            "items_to_receive":[{"appid":570,"classid":"5","instanceid":"0","amount":"1"}]},
            "descriptions":[{"appid":570,"classid":"5","instanceid":"0","name":"Dota item","icon_url":"dota"},
                {"appid":730,"classid":"5","instanceid":"2","market_name":"CS item","icon_url":"cs"}]}});
        let trade = parse_api_offer(&body, "42").unwrap();
        assert_eq!(trade.giving[0].name, "CS item");
        assert_eq!(trade.giving[0].amount, 3);
        assert_eq!(trade.receiving[0].app_id, 570);
        assert_eq!(trade.partner_id.as_deref(), Some("76561197960265851"));
        assert!(parse_api_offer(&body, "43").is_err());
    }

    #[test]
    fn html_reads_hover_json_without_executing_scripts() {
        let html = r#"<div class="tradeoffer" id="tradeoffer_42"><div class="trade_item" id="give"></div><div class="trade_item" id="receive"><span class="trade_item_amount">2</span></div></div>
        <script>var oItem = {"appid":730,"name":"A \"rare\" item","icon_url":"cs"}; oItem.foo = 1; BuildHover('give', oItem, UserYou, UserThem);
        BuildHover("receive", {"appid":570,"name":"Dota item","icon_url":"dota"}, UserThem, UserYou);</script>"#;
        let trade = parse_trade_html(html, "42").unwrap();
        assert_eq!(trade.giving[0].name, "A \"rare\" item");
        assert_eq!(trade.receiving[0].amount, 2);
        assert!(parse_trade_html(&html.replace("tradeoffer_42", "tradeofferid_42"), "42").is_ok());
        assert!(parse_trade_html(html, "43").is_err());
        assert!(
            parse_trade_html(
                &html.replace("UserYou, UserThem", "Unknown, UserThem"),
                "42"
            )
            .is_err()
        );
    }

    #[test]
    fn steam_cards_show_the_game_they_belong_to() {
        let item = item_from_description(&serde_json::json!({"appid":753,"market_fee_app":440,"app_name":"Steam","name":"Trading card"}),1).unwrap();
        assert_eq!(item.app_id, 440);
        assert!(item.game.is_empty());
        let tagged = item_from_description(&serde_json::json!({"appid":753,"name":"Card","tags":[{"category":"Game","localized_tag_name":"Team Fortress 2"}]}),1).unwrap();
        assert_eq!(tagged.game, "Team Fortress 2");
    }

    #[test]
    fn reports_auth_and_remote_errors() {
        assert!(
            validate_mobile_response(serde_json::json!({"success":true,"needauth":true})).is_err()
        );
        assert!(
            validate_mobile_response(serde_json::json!({"success":false,"needsauth":true}))
                .unwrap_err()
                .contains("Сессия")
        );
        assert_eq!(
            validate_mobile_response(serde_json::json!({"success":false,"message":"Expired"}))
                .unwrap_err(),
            "Expired"
        );
        assert!(validate_mobile_response(serde_json::json!({"success":true})).is_ok());
    }

    #[test]
    fn images_use_public_steam_hosts() {
        assert!(steam_image_url("//avatars.steamstatic.com/avatar.jpg").is_some());
        assert!(steam_image_url("https://steamstatic.com.evil.example/avatar.jpg").is_none());
        assert!(steam_image_url("file:///C:/secret.png").is_none());
    }
}
