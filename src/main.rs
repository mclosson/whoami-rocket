#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate crypto;
extern crate data_encoding;
extern crate dotenv;
extern crate postgres;
extern crate rand;
extern crate rocket_contrib;
extern crate rocket;
extern crate rustc_serialize;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

mod rails_session_cookie;

use dotenv::dotenv;
use postgres::{Connection, TlsMode};
use rocket::http::Cookies;
use std::env;
use std::process;
use std::str;
use rails_session_cookie::decrypt;

#[derive(Deserialize)]
struct RailsSessionCookie {
    user_id: i32,
    _session_id: String,
}

#[derive(Serialize)]
struct User {
    id: i32,
    email: String,
}

fn get_env_var_or_exit(name: &str) -> String {
    let value = match env::var(name) {
        Ok(v) => v,
        Err(_) => {
            println!("Need {}!", name);
            process::exit(1);
        }
    };

    value
}

#[get("/whoami")]
fn whoami(cookies: &Cookies) -> String {

    // Read configuration values from environment
    dotenv().ok();
    let cookie_name = get_env_var_or_exit("RAILS_COOKIE_NAME");
    let secret_key_base = get_env_var_or_exit("RAILS_SECRET_KEY_BASE");
    let connection_string = get_env_var_or_exit("RAILS_CONNECTION_STRING");

    // Extract Rails session cookie
    let cookie = cookies.find(&cookie_name);
    let session_cookie: String;
    let user: User;

    if let Some(c) = cookie {
        session_cookie = c.value().to_string();
    }
    else {
        return String::from("Give me a cookie!");
    }

    // Decrypt cookie
    let plain_text = ::decrypt(&session_cookie, &secret_key_base);

    // Deserialize json string into RailsCookie struct
    let rails_cookie: RailsSessionCookie = match serde_json::from_str(&plain_text) {
        Ok(value) => value,
        Err(e) => return format!("Error deserializing cookie: {}", e)
    };

    let user_id = rails_cookie.user_id;

    // Lookup user_id value in database
    let conn = match Connection::connect(connection_string, TlsMode::None) {
        Ok(connection) => connection,
        Err(e) => return format!("Could not connect to database: {}", e)
    };

    for row in &conn.query("SELECT id, email FROM users WHERE id = $1", &[&user_id]).unwrap() {
        user = User { id: row.get(0), email: row.get(1), };
        return serde_json::to_string(&user).expect("Error serializing user");
    }

    format!("No user found for user_id: {}\n", user_id)
}

fn main() {
    rocket::ignite().mount("/", routes![whoami]).launch();
}
