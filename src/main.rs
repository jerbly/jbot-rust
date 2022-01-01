use base64;
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
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

const MALFORMED_REQUEST: &str = "{\"type\":\"message\",\"text\":\"Error: Malformed request\"}";
const UNAUTHORIZED_CLIENT: &str = "{\"type\":\"message\",\"text\":\"Error: Unauthorized client\"}";

type HmacSha256 = Hmac<Sha256>;

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
                match handle_message(&bytes) {
                    Ok(body) => return Response::builder().body(body),
                    Err(err_body) => {
                        return Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(err_body)
                    }
                }
            } else {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(String::from(UNAUTHORIZED_CLIENT))
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

fn handle_message(bytes: &Bytes) -> Result<String, String> {
    let request_message: TeamsMessage = match serde_json::from_slice(&bytes) {
        Ok(msg) => msg,
        Err(_) => return Err(String::from(MALFORMED_REQUEST)),
    };

    let response_message: TeamsMessage = TeamsMessage {
        r#type: "message".to_string(),
        text: get_jira_link(request_message.text.as_str()),
    };

    Ok(
        serde_json::to_string(&response_message)
            .expect("Failed to serialize the response message."),
    )
}

fn get_jira_link(text: &str) -> String {
    lazy_static! {
        static ref JIRA_HOST: String = env::var("jira_host").unwrap_or("jira".to_string());
        static ref RE: Regex = Regex::new(r#"[A-Z0-9]+-[0-9]+"#).unwrap();
    }
    let tickets: Vec<&str> = RE.find_iter(text).map(|mat| mat.as_str()).collect();

    if tickets.len() == 1 {
        format!(
            "<a href=\"http://{0}/browse/{1}\">{1}</a>",
            JIRA_HOST.as_str(),
            tickets[0]
        )
    } else if tickets.len() > 1 {
        format!(
            "<a href=\"http://{}/issues/?jql=key%20in%20({})\">Found {} tickets</a>",
            JIRA_HOST.as_str(),
            tickets.join(","),
            tickets.len()
        )
    } else {
        "No tickets found".to_string()
    }
}

fn is_authorized(auth: String, bytes: &Bytes) -> bool {
    lazy_static! {
        static ref SECURITY_TOKEN: String =
            env::var("security_token").expect("The security_token env var is required");
    }
    let security_token_bytes =
        base64::decode(SECURITY_TOKEN.as_str()).expect("Security token should always decode");

    let mut mac =
        HmacSha256::new_from_slice(&security_token_bytes).expect("HMAC can take key of any size");
    mac.update(bytes);
    let result = mac.finalize();
    let signature = base64::encode(result.into_bytes());
    let auth_token = auth.split(' ').nth(1).unwrap_or("BAD AUTH");
    signature.as_str() == auth_token
}

#[cfg(test)]
mod tests {
    use crate::{get_jira_link, handle_message, is_authorized, MALFORMED_REQUEST};
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
        let result = handle_message(&bytes).unwrap();
        assert_eq!(
            String::from("{\"type\":\"message\",\"text\":\"No tickets found\"}"),
            result
        );
    }

    #[test]
    fn handle_message_malformed() {
        let bytes = Bytes::from_static(b"{\"not\":\"valid\",\"teams\":\"message\"}");
        match handle_message(&bytes) {
            Ok(_) => assert!(false, "Serialization should fail here."),
            Err(e) => assert!(e == MALFORMED_REQUEST),
        };
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
