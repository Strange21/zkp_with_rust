use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{async_trait, server, transport::{Server}, Code, Request, Response, Status};
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use zkp_chum_pederson::ZKP;
use zkp_auth::{auth_server::{Auth, AuthServer}, AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};


#[derive(Debug, Default)]
pub struct AuthImpl{
    pub user_info:Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user_name : Mutex<HashMap<String, String>>,
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

        user_info_lock.insert(user_name.clone(), user_info);
        println!("✅ Successful Registration username: {:?}", user_name);
        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(&self, challage_request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status>{
        println!("Request : {:?}", challage_request);
        let request = challage_request.into_inner();

        let user_name = request.user;

        let user_info_hash_map = &mut self.user_info.lock().unwrap();
        if let Some(user_info) = user_info_hash_map.get_mut(&user_name){
            let (_, _, _, q) = ZKP::get_contants();
            let c = ZKP::generate_random_number(&q);
            let auth_id = ZKP::generate_randome_string(12);

            user_info.c = c.clone();
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let auth_to_user_id = &mut self.auth_id_to_user_name.lock().unwrap();

            auth_to_user_id.insert(auth_id.clone(), user_name);
            Ok(Response::new(AuthenticationChallengeResponse{ auth_id: auth_id, c: c.to_bytes_be() }))
        }else{
            Err(Status::new(Code::NotFound, format!("User {} not found", user_name)))
        }
        
    }

    async fn verify_authentication(&self, answer_request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status>{
        println!("Processing Verification : {:?}", answer_request);
        let request = answer_request.into_inner();

        let auth_id = request.auth_id;

        let user_info_hash_map = &mut self.auth_id_to_user_name.lock().unwrap();

        if let Some(user_name) = user_info_hash_map.get(&auth_id){
            let user_name_has_map: &mut std::sync::MutexGuard<'_, HashMap<String, UserInfo>> = &mut self.user_info.lock().unwrap();
            let user_info = user_name_has_map.get_mut(user_name).expect("User name not found");
            let s = BigUint::from_bytes_be(&request.s);
            user_info.s = s;

            let (alpha, beta, p, q) = ZKP::get_contants();
            let zkp = ZKP{
                alpha, beta, p, q
            };

            // println!("r1: {}", user_info.r1);
            // println!("r2: {}", user_info.r2);
            // println!("y1: {}", user_info.y1);
            // println!("y2: {}", user_info.y2);
            // println!("s: {}", user_info.s);
            // println!("c: {}", user_info.c);
            let verification = zkp.verify(&user_info.r1, &user_info.r2, &user_info.y1, &user_info.y2, &user_info.s, &user_info.c);

            if verification{
                let session_id = ZKP::generate_randome_string(12);
                println!("✅ Correct Challenge Solution username: {:?}", user_name);
                return Ok(Response::new(AuthenticationAnswerResponse{session_id}));
            }else{
		        println!("❌ Wrong Challenge Solution username: {:?}", user_name);
                return Err(Status::new(Code::PermissionDenied, format!("AuthId {}: Bad solution to the challange", auth_id)));
            }

        }else{
            return Err(Status::new(Code::NotFound, format!("auth id {} not found in the database", auth_id)));
        }
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