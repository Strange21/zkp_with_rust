use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{async_trait, server, transport::{Server}, Code, Request, Response, Status};
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{auth_server::{Auth, AuthServer}, AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};


#[derive(Debug, Default)]
pub struct AuthImpl{
    pub user_info:Mutex<HashMap<String, UserInfo>>,
}

#[derive(Debug, Default)]
pub struct UserInfo{
    pub user_nmae: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub c: BigUint,
    pub s: BigUint,
    pub r1: BigUint,
    pub r2: BigUint,
    pub session_id: String,
}

#[async_trait]
impl Auth for AuthImpl{
    async fn register(&self, register_requerst:Request<RegisterRequest> ) -> Result<Response<RegisterResponse>, Status>{
        println!("Request : {:?}", register_requerst);
        let request = register_requerst.into_inner();

        let user_name = request.user;
        let mut user_info = UserInfo::default();

        user_info.user_nmae = user_name.clone();
        user_info.y1 = BigUint::from_bytes_be(&request.y1);
        user_info.y2 = BigUint::from_bytes_be(&request.y2);

        let user_info_lock = &mut self.user_info.lock().unwrap();

        user_info_lock.insert(user_name, user_info);
        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(&self, challage_request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status>{
        todo!();
    }

    async fn verify_authentication(&self, answer_request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status>{
        todo!();
    }
}

#[tokio::main]
async fn main(){

    let addr = "127.0.0.1:50051".to_string();
    println!("Hi This is a Server runing on {}", addr);
    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Unable to parse the address"))
        .await
        .unwrap();
}