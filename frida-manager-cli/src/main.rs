use download_rs::async_download::Download;
use reqwest;
use select::document::Document;
use select::predicate::Name;
use std::env;
use std::io::{self, Write};
async fn fetch_hrefs(url: &str) -> Result<Vec<String>, reqwest::Error> {
    // Make the GET request
    let response = reqwest::get(url).await?;
    // Check if the request was successful (status code 2xx)
    if response.status().is_success() {
        // Read the response body as a string
        let html_content = response.text().await?;
        // Parse the HTML content
        let document = Document::from_read(html_content.as_bytes()).expect("Failed to parse HTML");
        // Return href attributes from anchor (a) tags containing "/tag"
        let hrefs: Vec<String> = document
            .find(Name("a"))
            .filter_map(|node| node.attr("href"))
            .map(|href| href.to_string())
            .collect();

        // println!("{:?}",hrefs);
        return Ok(hrefs);
    } else {
        // Print an error message if the request was not successful
        eprintln!("Request failed with status code: {}", response.status());
        Err(response.error_for_status().unwrap_err())
    }
}

#[tokio::main]
async fn main() {
    let _ = get_server().await;
}

async fn get_server() {
    let releases_url = "https://github.com/frida/frida/releases";
    let tag_base = "https://github.com/frida/frida/releases/tag/";
    let download_base = "https://github.com/frida/frida/releases/download";
    let github = "https://github.com";

    let releases = fetch_hrefs(releases_url).await.unwrap();
    // get only tags
    let tags: Vec<_> = releases
        .iter()
        .filter(|href| href.contains("/tag/"))
        .map(|href| {
            return format!("{}{}", github, href);
        })
        .collect();

    let options: Vec<String> = tags
        .iter()
        .map(|option| {
            return option.replace(tag_base, "");
        })
        .collect();

    let release_version = get_option_from(&options);

    let android_chips = vec!["arm64".to_string(), "x86".to_string()];
    let chip_choice = get_option_from(&android_chips);

    println!(
        "Downloading Frida server : {} for Android : {}",
        release_version, chip_choice
    );

    let download_url = format!(
        "{}/{}/frida-server-{}-android-{}.xz",
        download_base, release_version, release_version, chip_choice
    )
        .to_string();

    let path = download_file(&download_url).await.unwrap();
    println!("{}", path)
}

async fn download_file(url: &str) -> Result<String, reqwest::Error> {
    let download_path = env::current_exe().unwrap();
    println!(
        "download path should be : {:?}",
        download_path.parent().unwrap()
    );

    let download_request = Download::new(url, None, None);
    return match download_request.download() {
        Ok(_) => Ok(download_path
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()),
        Err(error) => {
            println!("{}", error);
            Ok("error".to_string())
        }
    };
}

fn get_option_from(options: &Vec<String>) -> String {
    for (index, option) in options.iter().enumerate() {
        println!("{} -> {}", index + 1, option);
    }

    print!("Enter the number of the frida release: ");
    // Flush the buffer to ensure the prompt is shown
    io::stdout().flush().unwrap();
    let mut choice = String::new();
    io::stdin()
        .read_line(&mut choice)
        .expect("Failed to read line");

    // Parse and handle the user's choice
    return match choice.trim().parse::<usize>() {
        Ok(index) if index > 0 && index <= options.len() => {
            let chosen_option = &options[index - 1];
            String::from(chosen_option)
        }
        _ => "".to_string(),
    };
}
