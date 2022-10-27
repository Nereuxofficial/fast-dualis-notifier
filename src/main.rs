use itertools::Itertools;
use lambda_runtime::{service_fn, Error as LambdaError, LambdaEvent};
use reqwest::header::HeaderMap;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use urlencoding::encode;

const USER: &str = include_str!("user.txt");
const PASS: &str = include_str!("pass.txt");
const WEBHOOK_URL: &str = include_str!("webhook.txt");
// AWS Lambda wants us to use /tmp as storage directory
const STORAGE: &str = "/tmp/";

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    let func = service_fn(func);
    lambda_runtime::run(func).await?;
    Ok(())
}

async fn func(event: LambdaEvent<Value>) -> Result<Value, LambdaError> {
    let (event, _context) = event.into_parts();
    let semester_ids = event["semester"]
        .as_str()
        .unwrap_or("-N000000015098000,-N000000015088000,-N000000015108000,-N000000015118000")
        .split(',');
    let client = Client::new();
    let (cookie, session) = get_session(client.clone()).await.unwrap();
    let mut diffs = vec![];
    for semester in semester_ids {
        let differences = get_differences(semester, &cookie, &session).await;
        if let Some(difference) = &differences {
            send_webhook(client.clone(), difference.as_str()).await;
            diffs.push(difference.clone());
        }
    }
    Ok(json!({
        "message": format!("Classes changed: {diffs:?}")
    }))
}

async fn send_webhook(client: Client, class: &str) -> StatusCode {
    client
        .post(WEBHOOK_URL)
        .header("Content-Type", "application/json")
        .body(
            r#"{
  "content": " ",
  "embeds": [
    {
      "title": "Die Noten für <Fach> sind verfügbar!",
      "description": "Gehe auf https://dualis.dhbw.de um deine Note zu erfahren",
      "url": "https://dualis.dhbw.de",
      "color": 16734296
    }
  ],
  "attachments": []
}"#
            .replace("<Fach>", class),
        )
        .send()
        .await
        .unwrap()
        .status()
}

/// It gets the new grades, gets the old grades, compares them, and saves the new grades
///
/// Arguments:
///
/// * `semester_id`: The ID of the semester you want to check.
/// * `cookie`: The cookie that you get from the login request.
/// * `session`: The session ID that you get from the login request.
///
/// Returns:
///
/// An Option containing the class with the new grade or None.
async fn get_differences(semester_id: &str, cookie: &str, session: &str) -> Option<String> {
    let client = Client::new();
    let new_grades = &get_grades(client, cookie, session, semester_id)
        .await
        .expect("Failed to get new grades");
    let old_grades = load_grades(semester_id).await;
    if old_grades.is_err() {
        return None;
    }
    let mut diff: Option<String> = None;
    new_grades
        .iter()
        .sorted()
        .zip(old_grades.unwrap().iter().sorted())
        .for_each(|(new, old)| {
            if new != old {
                diff = Some(new.0.clone())
            }
        });
    save_grades(semester_id, new_grades).await.unwrap();
    diff
}

/// We send a POST request to the login page with our credentials and get a cookie and a session in
/// return
///
/// Arguments:
///
/// * `client`: The client we created earlier
///
/// Returns:
///
/// A tuple of two strings. The first string is the cookie, the second string is the session.
async fn get_session(client: Client) -> Result<(String, String), Box<dyn std::error::Error>> {
    let passwd = encode(PASS);
    let payload = format!("usrname={USER}%40student.dhbw-mannheim.de&pass={passwd}&APPNAME=CampusNet&PRGNAME=LOGINCHECK&ARGUMENTS=clino%2Cusrname%2Cpass%2Cmenuno%2Cmenu_type%2Cbrowser%2Cplatform&clino=000000000000001&menuno=000324&menu_type=classic&browser=&platform=");
    let response = client
        .post("https://dualis.dhbw.de/scripts/mgrqispi.dll")
        .headers(get_headers(HeaderType::Necessary))
        .body(payload)
        .send()
        .await?;
    let headers = response.headers();
    let cookie = headers
        .get("Set-Cookie")
        .unwrap()
        .to_str()?
        .split(';')
        .collect::<Vec<&str>>()[0]
        .replace(' ', "");
    // We have these weird -N Arguments in the header that we need to parse to get our session
    let session = headers
        .get("refresh")
        .unwrap()
        .to_str()?
        .split("ARGUMENTS=")
        .collect::<Vec<&str>>()[1]
        .split(',')
        .collect::<Vec<&str>>()[0];
    Ok((cookie, String::from(session)))
}

/// It sends a GET request to the Dualis server, which returns the grades of the current semester
///
/// Arguments:
///
/// * `client`: The client that is used to send the request.
/// * `cookie`: The cookie you got from the login request
/// * `session`: The session id of the user.
/// * `semester_id`: The semester id of the semester you want to get the grades from.
///
/// Returns:
///
/// A String of html
async fn get_grades(
    client: Client,
    cookie: &str,
    session: &str,
    semester_id: &str,
) -> Result<HashMap<String, Option<String>>, Box<dyn std::error::Error>> {
    let response = client.get(format!("https://dualis.dhbw.de/scripts/mgrqispi.dll?APPNAME=CampusNet&PRGNAME=COURSERESULTS&ARGUMENTS={session},-N000307,{semester_id}"))
        .headers(get_headers(HeaderType::Necessary))
        .header("Cookie", cookie)
        .send()
        .await?
        .text()
        .await?;
    parse_grades(&response)
}

/// Parses the grades from an HTML Response
fn parse_grades(html: &str) -> Result<HashMap<String, Option<String>>, Box<dyn Error>> {
    let table = table_extract::Table::find_first(html).unwrap();
    let rows = table.iter();
    let mut grades = vec![];
    // This is complicated because the DHBW site gives us absolute garbage html, which we sadly need
    // to parse
    rows.filter(|r| !r.is_empty()).for_each(|row| {
        let row_slice: Vec<String> = row
            .iter()
            .map(|c| c.trim_end_matches(&['\r', '\n', '\t']).to_string())
            .collect();
        grades.push((row_slice[1].clone(), row_slice[2].clone()));
    });
    let mut parsed_grades: HashMap<String, Option<String>> = HashMap::new();
    for grade in grades.iter().skip(1) {
        parsed_grades.insert(
            grade.0.clone(),
            grade.1.find(',').map(|grade_position| grade.1[grade_position - 1..grade_position + 2].to_string()),
        );
    }
    Ok(parsed_grades)
}

#[derive(PartialEq, Eq, Clone, Debug)]
enum HeaderType {
    Necessary,
    Optional,
}

/// It creates a new `HeaderMap` and inserts some headers into it
/// Use HeaderType::Optional for more legit looking requests.
/// A HeaderMap with the given Header level
fn get_headers(header_type: HeaderType) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if header_type == HeaderType::Optional {
        // Optional headers to make the request look more like a browser
        headers.insert(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
                .parse()
                .unwrap(),
        );
        headers.insert("Accept-Encoding", "gzip, deflate, br".parse().unwrap());
        headers.insert(
            "Accept-Language",
            "en-US,en;q=0.9,de;q=0.8".parse().unwrap(),
        );
        headers.insert("Cache-Control", "max-age=0".parse().unwrap());
        headers.insert("Connection", "keep-alive".parse().unwrap());
        headers.insert("Host", "dualis.dhbw.de".parse().unwrap());
        headers.insert("Upgrade-Insecure-Requests", "1".parse().unwrap());
        // Firefox user agent
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "Referer",
            "https://dualis.dhbw.de/scripts/mgrqispi.dll"
                .parse()
                .unwrap(),
        );
    }
    headers.insert(
        "Content-Type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    headers
}

async fn save_grades(
    semester_id: &str,
    grades: &HashMap<String, Option<String>>,
) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("{STORAGE}{semester_id}.json"))
        .await
        .unwrap();
    file.write_all(serde_json::to_string(grades).unwrap().as_bytes())
        .await?;
    Ok(())
}

async fn load_grades(semester_id: &str) -> Result<HashMap<String, Option<String>>, Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(format!("{STORAGE}{semester_id}.json"))
        .await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    Ok(serde_json::from_str(&contents)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::ClientBuilder;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_session() {
        let client = ClientBuilder::new().build().unwrap();
        let (cookie, session) = get_session(client).await.unwrap();
        println!("cookie: {cookie} \n session: {session}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_send_webhook() {
        assert_eq!(204, send_webhook(Client::new(), "Programmieren").await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_grades() {
        let client = ClientBuilder::new().build().unwrap();
        let (cookie, session) = get_session(client.clone()).await.unwrap();
        get_grades(client, &cookie, &session, "-N000000015098000")
            .await
            .unwrap();
    }

    #[test]
    fn test_parse_grades() {
        let document = include_str!("../example.html");
        let grades = parse_grades(document).unwrap();
        println!("{grades:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_and_parse_grades() {
        let semester_id = "-N000000015098000";
        let client = ClientBuilder::new().build().unwrap();
        let (cookie, session) = get_session(client.clone()).await.unwrap();
        let parsed_grades = get_grades(client, &cookie, &session, semester_id)
            .await
            .unwrap();
        save_grades(semester_id, &parsed_grades).await.unwrap();
        println!("{parsed_grades:?}");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn load_and_parse_grades() {
        let semester_id = "-N000000015098000";
        let grades = load_grades(semester_id).await.unwrap();
        println!("{grades:?}");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_differences() {
        let semester_id = "-N000000015098000";
        let client = ClientBuilder::new().build().unwrap();
        let (cookie, session) = get_session(client.clone()).await.unwrap();
        let differences = get_differences(semester_id, &cookie, &session).await;
        println!("{differences:?}");
    }
}
