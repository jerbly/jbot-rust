use base64;
use hmac::{Hmac, Mac};
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use std::{env, net::Ipv4Addr};
use warp::{
    http::Response,
    hyper::{body::Bytes, StatusCode},
    Filter,
};

#[derive(Deserialize, Serialize)]
struct TeamsMessage {
    r#type: String,
    text: String,
}

#[tokio::main]
async fn main() {
    let teams_filter = warp::post()
        .and(warp::path!("api" / "TeamsTrigger"))
        .and(warp::header("Authorization"))
        .and(warp::body::bytes())
        .map(|auth: String, bytes: Bytes| {
            if is_authorized(auth, &bytes) {
                Response::builder().body(handle_message(&bytes))
            } else {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(String::from("Unauthorized"))
            }
        });

    let port_key = "FUNCTIONS_CUSTOMHANDLER_PORT";
    let port: u16 = match env::var(port_key) {
        Ok(val) => val.parse().expect("Custom Handler port is not a number!"),
        Err(_) => 3000,
    };

    warp::serve(teams_filter)
        .run((Ipv4Addr::UNSPECIFIED, port))
        .await
}

fn handle_message(bytes: &Bytes) -> String {
    let mut teams_message: TeamsMessage = serde_json::from_slice(&bytes).unwrap();
    teams_message.text = get_jira_link(teams_message.text.as_str());
    serde_json::to_string(&teams_message).unwrap()
}

fn get_jira_link(text: &str) -> String {
    let jira_host = env::var("jira_host").unwrap_or("jira".to_string());
    let re = Regex::new(r#"[A-Z0-9]+-[0-9]+"#).unwrap();

    let tickets: Vec<&str> = re.find_iter(text).map(|mat| mat.as_str()).collect();

    if tickets.len() == 1 {
        format!(
            "<a href=\"http://{0}/browse/{1}\">{1}</a>",
            jira_host, tickets[0]
        )
    } else if tickets.len() > 1 {
        format!(
            "<a href=\"http://{}/issues/?jql=key%20in%20({})\">Found {} tickets</a>",
            jira_host,
            tickets.join(","),
            tickets.len()
        )
    } else {
        "No tickets found".to_string()
    }
}

fn is_authorized(auth: String, bytes: &Bytes) -> bool {
    let security_token = env::var("security_token").unwrap();
    let auth_token = auth.split(' ').nth(1).unwrap();
    type HmacSha256 = Hmac<Sha256>;
    let security_token_bytes = base64::decode(security_token).unwrap();
    let mut mac =
        HmacSha256::new_from_slice(&security_token_bytes).expect("HMAC can take key of any size");
    mac.update(bytes);
    let result = mac.finalize();
    let signature = base64::encode(result.into_bytes());
    signature.as_str() == auth_token
}

#[cfg(test)]
mod tests {
    use crate::{get_jira_link, handle_message, is_authorized};
    use std::env;
    use warp::hyper::body::Bytes;

    fn setup_env() {
        env::set_var(
            "security_token",
            "35kwPoeC1whop4lX68yqGPpg9WrVV3CTpu8rS29x+SU=",
        );
    }

    #[test]
    fn handle_message_good() {
        let bytes = Bytes::from_static(b"{\"type\":\"message\",\"text\":\"Nothing\"}");
        let result = handle_message(&bytes);
        assert_eq!(
            String::from("{\"type\":\"message\",\"text\":\"No tickets found\"}"),
            result
        );
    }

    #[test]
    fn handle_message_malformed() {
        let bytes = Bytes::from_static(b"{\"not\":\"valid\",\"teams\":\"message\"}");
        let result = handle_message(&bytes);
        assert_eq!(
            String::from("{\"type\":\"message\",\"text\":\"No tickets found\"}"),
            result
        );
    }

    #[test]
    fn get_jira_link_many() {
        let result = get_jira_link("Ticket one is BACKLOG-1234 and two is MED-789");
        assert_eq!(result, "<a href=\"http://jira/issues/?jql=key%20in%20(BACKLOG-1234,MED-789)\">Found 2 tickets</a>");
    }

    #[test]
    fn get_jira_link_one() {
        let result = get_jira_link("The one is BACKLOG-1234");
        assert_eq!(
            result,
            "<a href=\"http://jira/browse/BACKLOG-1234\">BACKLOG-1234</a>"
        );
    }

    #[test]
    fn get_jira_link_none() {
        let result = get_jira_link("Nothing here");
        assert_eq!(result, "No tickets found");
    }

    #[test]
    fn is_authorized_false() {
        setup_env();
        let auth = String::from("HMAC FAKEGtJVnQbecZogqfLxZd/GNOFCm2Fp0Ikyr6utmCc=");
        let bytes = Bytes::from_static(
            b"{\"type\":\"message\",\"text\":\"Ticket one is BACKLOG-1234 and two is MED-789\"}",
        );
        let result = is_authorized(auth, &bytes);
        assert_eq!(false, result);
    }

    #[test]
    fn is_authorized_true() {
        setup_env();
        let auth = String::from("HMAC tqSwGtJVnQbecZogqfLxZd/GNOFCm2Fp0Ikyr6utmCc=");
        let bytes = Bytes::from_static(
            b"{\"type\":\"message\",\"text\":\"Ticket one is BACKLOG-1234 and two is MED-789\"}",
        );
        let result = is_authorized(auth, &bytes);
        assert_eq!(true, result);
    }
}
