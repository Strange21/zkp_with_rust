use zkp_chum_pederson::ZKP;
use std::io::stdin;
use num_bigint::BigUint;
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};


#[tokio::main]
async fn main(){
    let mut buf = String::new();
    let (alpha, beta, p, q) = ZKP::get_contants();

    let zkp = ZKP{
        alpha: alpha.clone(),
        beta:beta.clone(),
        p: p.clone(),
        q:q.clone(),
    };

    let mut client = AuthClient::connect("http://127.0.0.1:50051".to_string()).await.expect("Unable to connect to the server");

    println!("Enter the user name");
    stdin().read_line(&mut buf).expect("Unable to read the username");
    let username = buf.trim().to_string();
    println!("Enter the password");
    buf.clear();
    stdin().read_line(&mut buf).expect("Unable to read the password");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let y1 = ZKP::exponentiate(&alpha, &password, &p);
    let y2 = ZKP::exponentiate(&beta, &password, &p);


    let register_request = RegisterRequest{
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    println!("Enter the password (to login)");
    // buf.clear();
    stdin().read_line(&mut buf).expect("Unable to read the username");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());

    let a = client.register(register_request).await.expect("error while registerring the client"); 

    let k = ZKP::generate_random_number(&q);
    let r1 = ZKP::exponentiate(&alpha, &k, &q);
    let r2 = ZKP::exponentiate(&beta, &k, &q);

    let auth_challange = AuthenticationChallengeRequest{user: username, r1: r1.to_bytes_be(), r2:r2.to_bytes_be()};
    let response = client.create_authentication_challenge(auth_challange).await.unwrap().into_inner();

    println!("Response : {:?}", response);

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    let s = zkp.solve(&k, &c, &password);

    let auth_response = AuthenticationAnswerRequest{auth_id: auth_id, s:s.to_bytes_be()};
    let session = client.verify_authentication(auth_response).await.unwrap().into_inner();

    println!("you ar logged in with session Id: {}", session.session_id);

}