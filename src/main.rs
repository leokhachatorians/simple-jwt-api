#[macro_use]
extern crate rocket;

use chrono::{Duration, Utc};

use rocket::http::Status;

use jsonwebtoken::{
    decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use rocket::http::ContentType;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{self, Responder, Response};
use rocket::serde::json::{json, Value};
use rocket::serde::{Deserialize, Serialize};

#[catch(401)]
fn unauthorized_catcher(req: &Request) -> Value {
    let v = req.local_cache(|| "".to_owned());
    json!({ "message": v })
}

#[derive(Debug)]
pub struct ApiResponse {
    pub message: Value,
    pub status: Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

impl<'a> Responder<'a, 'static> for ApiResponse {
    fn respond_to(self, req: &'a Request<'_>) -> response::Result<'static> {
        Response::build_from(self.message.respond_to(req).unwrap())
            .status(self.status)
            .header(ContentType::JSON)
            .ok()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Token {
    claims: Claims,
    header: Header,
}

#[derive(Debug)]
enum JwtError {
    Invalid,
    Missing,
}

#[rocket::async_trait]
impl<'a> FromRequest<'a> for Token {
    type Error = JwtError;

    async fn from_request(req: &'a Request<'_>) -> Outcome<Self, Self::Error> {
        let mut error_message =
            "Bad Authorization Header. Expected 'Authorization: Bearer' <JWT>".to_owned();
        let mut error_type = JwtError::Missing;
        if let Some(jwt_header) = req.headers().get_one("Authorization") {
            let jwt_header = jwt_header.split_whitespace().collect::<Vec<_>>();

            if jwt_header.len() != 2 || jwt_header[0] != "Bearer" {
                return Outcome::Failure((Status::Unauthorized, error_type));
            }
            match decode_token(jwt_header[1]) {
                Ok(token) => {
                    return Outcome::Success(Token {
                        header: token.header,
                        claims: token.claims,
                    })
                }
                Err(err) => {
                    error_message = fetch_error_message(err.kind());
                    error_type = JwtError::Invalid;
                }
            }
        }
        req.local_cache(|| error_message);
        Outcome::Failure((Status::Unauthorized, error_type))
    }
}

fn fetch_error_message(err: &ErrorKind) -> String {
    let message = match err {
        ErrorKind::ExpiredSignature => "Signature has expired",
        ErrorKind::InvalidIssuer => "Invalid Issuer",
        ErrorKind::InvalidAudience => "Invalid Audience",
        ErrorKind::InvalidSubject => "Invalid Subject",
        ErrorKind::InvalidSignature => "Invalid Signature",
        ErrorKind::InvalidAlgorithm => "Invalid Algorithm",
        _ => "Invalid Token",
    };

    message.to_owned()
}

fn decode_token(token: &str) -> jsonwebtoken::errors::Result<TokenData<Claims>> {
    decode::<Claims>(
        &token,
        &DecodingKey::from_secret("secret".as_ref()),
        &Validation::default(),
    )
}

#[get("/token-required")]
fn token_required(_token: Token) -> ApiResponse {
    ApiResponse {
        message: json!({"message": "your in!"}),
        status: Status::Ok,
    }
}

#[get("/token")]
fn token() -> ApiResponse {
    let now = Utc::now();
    let exp = now.checked_add_signed(Duration::seconds(900)).unwrap();

    let claims = Claims {
        sub: "leo".to_string(),
        exp: exp.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )
    .unwrap();

    ApiResponse {
        message: json!({ "access_token": token }),
        status: Status::Ok,
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![token, token_required])
        .register("/", catchers![unauthorized_catcher])
}
