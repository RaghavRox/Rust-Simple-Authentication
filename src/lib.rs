use argon2::{self, Config};
use axum::{
    extract::{self, State},
    http::{self, header, HeaderMap},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    self,
    errors::{Error, ErrorKind},
    EncodingKey, Header, TokenData,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Row, Sqlite};
use uuid::{self, Uuid};

#[derive(Serialize, Deserialize, Debug)]
struct UserCredentials {
    username: String,
    password: String,
}

pub fn get_router(pool: Pool<Sqlite>) -> Router {
    Router::new()
        .route("/signup", get(signup))
        .route("/login", get(login))
        .route("/validate", get(validate))
        .with_state(pool)
}

async fn signup(
    State(pool): State<Pool<Sqlite>>,
    extract::Json(user_credentials): extract::Json<UserCredentials>,
) -> impl IntoResponse {
    let user = sqlx::query("INSERT INTO UserCredentials (username, password) VALUES (?, ?)")
        .bind(&user_credentials.username)
        .bind(hash_password(&user_credentials.password))
        .execute(&pool)
        .await;

    match user {
        Ok(_) => (
            http::StatusCode::CREATED,
            generate_token(30, b"testtesttesttesttesttest", user_credentials.username).unwrap(),
        ),
        Err(e) => (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {e}"),
        ),
    }
}

async fn login(
    State(pool): State<Pool<Sqlite>>,
    extract::Json(user_credentials): extract::Json<UserCredentials>,
) -> impl IntoResponse {
    let password = sqlx::query("SELECT password FROM UserCredentials WHERE username = ?")
        .bind(&user_credentials.username)
        .fetch_one(&pool)
        .await;

    let password = match password {
        Ok(p) => p,
        Err(e) => {
            return (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error: {e}"),
            )
                .into_response();
        }
    };

    let password = password.get::<String, _>(0);

    let valid = validate_password(&user_credentials.password, &password);
    match valid {
        Ok(is_valid) => {
            if is_valid {
                (
                    http::StatusCode::OK,
                    generate_token(30, b"testtesttesttesttesttest", user_credentials.username)
                        .unwrap(),
                )
                    .into_response()
            } else {
                (
                    http::StatusCode::UNAUTHORIZED,
                    "Invalid credentials".to_string(),
                )
                    .into_response()
            }
        }
        Err(e) => (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {e}"),
        )
            .into_response(),
    }
}

async fn validate(headers: HeaderMap) -> Response {
    let token = match headers.get(header::AUTHORIZATION) {
        Some(header) => match header.to_str() {
            Ok(s) => s,
            Err(e) => {
                return e.to_string().into_response();
            }
        },
        None => {
            return "No Authorization header found".into_response();
        }
    };

    let user = validate_token(b"testtesttesttesttesttest", token).await;

    match user {
        Ok(username) => (http::StatusCode::OK, username).into_response(),
        Err(e) => (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {e}"),
        )
            .into_response(),
    }
}

fn hash_password(password: &str) -> String {
    let salt = generate_salt();
    let config = Config::default();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    hash
}

fn generate_salt() -> [u8 ; 16] {
    let id = Uuid::new_v4();
    id.as_bytes().to_owned()
}

fn validate_password(password: &str, hash: &str) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(hash, password.as_bytes())
}



#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    sub: String,
    exp: i64,
}

fn encode_jwt(secret: &[u8], claims: &CustomClaims) -> Result<String, Error> {
    let header = Header::default();
    let key = EncodingKey::from_secret(secret);
    jsonwebtoken::encode(&header, claims, &key)
}

fn decode_jwt(secret: &[u8], token: &str) -> Result<TokenData<CustomClaims>, Error> {
    let key = jsonwebtoken::DecodingKey::from_secret(secret);
    let validation = Default::default();
    jsonwebtoken::decode::<CustomClaims>(token, &key, &validation)
}

fn generate_token(expiry_time: i64, secret_key: &[u8], user_id: String) -> Result<String, Error> {
    let claims = CustomClaims {
        sub: user_id,
        exp: (Utc::now() + Duration::seconds(expiry_time)).timestamp(),
    };
    encode_jwt(secret_key, &claims)
}

//validate the token and also check if it is expired or not
async fn validate_token(secret_key: &[u8], token: &str) -> Result<String, Error> {
    let token_data = decode_jwt(secret_key, token);
    let username = match token_data {
        Ok(data) => {
            if data.claims.exp < (Utc::now()).timestamp() {
                return Err(Error::from(ErrorKind::ExpiredSignature));
            }
            data.claims.sub
        }
        Err(e) => {
            return  Err(e);
        },
    };

    Ok(username)

    // //check if user is present in database
    // let result = sqlx::query("SELECT username FROM UserCredentials WHERE username = ?")
    //     .bind(&username)
    //     .fetch_one(&pool)
    //     .await;

    // match result {
    //     Ok(_) => Ok(username),
    //     Err(e) => Err(Error::from(ErrorKind::InvalidToken)),
    // }
}
