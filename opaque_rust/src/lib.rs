use std::fmt;

#[cfg(feature = "fast_argon2")]
use argon2_kdf::{Algorithm, Hasher};
#[cfg(feature = "fast_argon2")]
use opaque_ke::argon2;
#[cfg(not(feature = "fast_argon2"))]
use opaque_ke::argon2;
#[cfg(not(feature = "fast_argon2"))]
use opaque_ke::argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use opaque_ke::{ciphersuite::CipherSuite, errors::InternalError, errors::ProtocolError};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;

    //type Ksf = Argon2<'static>;
    type Ksf = CustomKsf;
}

enum Error {
    Protocol {
        context: &'static str,
        error: ProtocolError,
    },
    Internal {
        context: &'static str,
        error: InternalError,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol { context, error } => {
                write!(f, "opaque protocol error at \"{}\"; {}", context, error)
            }
            Error::Internal { context, error } => {
                write!(f, "Internal error at \"{}\"; {}", context, error)
            }
        }
    }
}

fn from_protocol_error(context: &'static str) -> impl Fn(ProtocolError) -> Error {
    move |error| Error::Protocol { context, error }
}

#[derive(Default)]
struct CustomKsf {
    #[cfg(not(feature = "fast_argon2"))]
    argon: Argon2<'static>,
    #[cfg(feature = "fast_argon2")]
    argon: Hasher<'static>,
}

impl Ksf for CustomKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();

        #[cfg(not(feature = "fast_argon2"))]
        self.argon
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;

        #[cfg(feature = "fast_argon2")]
        {
            let hash_result = self
                .argon
                .clone()
                .hash_length(L::to_u32())
                .hash(input.as_slice())
                .map_err(|_| InternalError::KsfError)?;

            let hash_bytes = hash_result.as_bytes();

            // Safety check: ensure lengths match before copying
            if hash_bytes.len() != output.len() {
                return Err(InternalError::KsfError);
            }
            output.copy_from_slice(hash_bytes);
        }

        Ok(output)
    }
}

#[cfg(not(feature = "fast_argon2"))]
fn build_argon2_ksf(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
) -> Result<Option<CustomKsf>, Error> {
    let mut param_builder = ParamsBuilder::default();
    param_builder.t_cost(t_cost);
    param_builder.m_cost(m_cost);
    param_builder.p_cost(parallelism);

    if let Ok(params) = param_builder.build() {
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        return Ok(Some(CustomKsf { argon }));
    }

    Err(Error::Internal {
        context: "Invalid keyStretching (argon2id) combination",
        error: InternalError::KsfError,
    })
}

#[cfg(feature = "fast_argon2")]
fn build_argon2_ksf(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
) -> Result<Option<CustomKsf>, Error> {
    let argon = Hasher::new()
        .salt_length(argon2::RECOMMENDED_SALT_LEN as u32)
        .custom_salt(&[0; argon2::RECOMMENDED_SALT_LEN])
        .algorithm(Algorithm::Argon2id)
        .iterations(t_cost)
        .memory_cost_kib(m_cost)
        .threads(parallelism);
    Ok(Some(CustomKsf { argon }))
}

fn get_custom_ksf(
    ksf_config: Option<KeyStretchingFunctionConfig>,
) -> Result<Option<CustomKsf>, Error> {
    let config = ksf_config
        .as_ref()
        .map(|c| c.variant)
        .unwrap_or(KeyStretchingFunctionVariant::RfcRecommended);

    match config {
        // https://www.rfc-editor.org/rfc/rfc9106.html#section-4-4.2
        KeyStretchingFunctionVariant::RfcHardDriveEncryption => {
            build_argon2_ksf(1, 6 * u32::pow(2, 20), 4)
        }
        //https://www.rfc-editor.org/rfc/rfc9106.html#section-4-4.1
        KeyStretchingFunctionVariant::RfcServerAuthentication => {
            build_argon2_ksf(1, u32::pow(2, 22), 8)
        }
        // https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1
        // https://www.rfc-editor.org/rfc/rfc9807.html#name-configurations
        // using the recommended parameters for Argon2id except we use 2^21-1 since 2^21 crashes in browsers
        KeyStretchingFunctionVariant::RfcRecommended => build_argon2_ksf(1, u32::pow(2, 21) - 1, 4),
        // https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.2
        KeyStretchingFunctionVariant::RfcMemoryConstrained => {
            build_argon2_ksf(3, u32::pow(2, 16), 4)
        }
        KeyStretchingFunctionVariant::Custom => {
            let config = ksf_config.unwrap();
            build_argon2_ksf(config.iterations, config.memory, config.parallelism)
        }
        _ => Err(Error::Internal {
            context: "Unsupported key stretching function variant",
            error: InternalError::KsfError,
        }),
    }
}

#[cxx::bridge]
mod opaque_ffi {

    enum KeyStretchingFunctionVariant {
        RfcHardDriveEncryption,
        RfcServerAuthentication,
        RfcRecommended,
        RfcMemoryConstrained,
        Custom,
    }

    struct KeyStretchingFunctionConfig {
        variant: KeyStretchingFunctionVariant,
        iterations: u32,
        memory: u32,
        parallelism: u32,
    }

    struct OpaqueStartClientRegistrationParams<'a> {
        password: &'a [u8],
    }

    struct OpaqueStartClientRegistrationResult {
        client_registration_state: Vec<u8>,
        registration_request: Vec<u8>,
    }

    struct OpaqueFinishClientRegistrationParams<'a> {
        password: &'a [u8],
        registration_response: &'a [u8],
        client_registration_state: &'a [u8],
        client_identifier: String,
        server_identifier: String,
        key_stretching_config: KeyStretchingFunctionConfig,
    }

    struct OpaqueFinishClientRegistrationResult {
        registration_record: Vec<u8>,
        export_key: Vec<u8>,
        server_static_public_key: Vec<u8>,
    }

    struct OpaqueStartClientLoginParams<'a> {
        password: &'a [u8],
    }

    struct OpaqueStartClientLoginResult {
        client_login_state: Vec<u8>,
        start_login_request: Vec<u8>,
    }

    struct OpaqueFinishClientLoginParams<'a> {
        client_login_state: &'a [u8],
        login_response: &'a [u8],
        password: &'a [u8],
        client_identifier: String,
        server_identifier: String,
        context: String,
        key_stretching_config: KeyStretchingFunctionConfig,
    }

    struct OpaqueFinishClientLoginResult {
        finish_login_request: Vec<u8>,
        session_key: Vec<u8>,
        export_key: Vec<u8>,
        server_static_public_key: Vec<u8>,
    }

    struct OpaqueCreateServerRegistrationResponseParams<'a> {
        server_setup: &'a [u8],
        user_identifier: String,
        registration_request: &'a [u8],
    }

    struct OpaqueCreateServerRegistrationResponseResult {
        registration_response: Vec<u8>,
    }

    struct OpaqueFinishServerRegistrationParams<'a> {
        message_bytes: &'a [u8],
    }

    struct OpaqueFinishServerRegistrationResult {
        password_file: Vec<u8>,
    }

    struct OpaqueStartServerLoginParams<'a> {
        server_setup: &'a [u8],
        registration_record: &'a [u8],
        start_login_request: &'a [u8],
        user_identifier: String,
        context: String,
        client_identifier: String,
        server_identifier: String,
    }

    struct OpaqueStartServerLoginResult {
        server_login_state: Vec<u8>,
        login_response: Vec<u8>,
    }

    struct OpaqueFinishServerLoginParams<'a> {
        server_login_state: &'a [u8],
        finish_login_request: &'a [u8],
        context: String,
        client_identifier: String,
        server_identifier: String,
    }

    struct OpaqueFinishServerLoginResult {
        session_key: Vec<u8>,
    }

    extern "Rust" {
        fn opaque_start_client_registration(
            params: OpaqueStartClientRegistrationParams,
        ) -> Result<OpaqueStartClientRegistrationResult>;

        fn opaque_finish_client_registration(
            params: OpaqueFinishClientRegistrationParams,
        ) -> Result<OpaqueFinishClientRegistrationResult>;

        fn opaque_start_client_login(
            params: OpaqueStartClientLoginParams,
        ) -> Result<OpaqueStartClientLoginResult>;

        fn opaque_finish_client_login(
            params: OpaqueFinishClientLoginParams,
        ) -> Result<UniquePtr<OpaqueFinishClientLoginResult>>;

        fn opaque_create_server_setup() -> Vec<u8>;

        fn opaque_get_server_public_key(data: &[u8]) -> Result<Vec<u8>>;

        fn opaque_create_server_registration_response(
            params: OpaqueCreateServerRegistrationResponseParams,
        ) -> Result<OpaqueCreateServerRegistrationResponseResult>;

        fn opaque_finish_server_registration(
            params: OpaqueFinishServerRegistrationParams,
        ) -> Result<OpaqueFinishServerRegistrationResult>;

        fn opaque_start_server_login(
            params: OpaqueStartServerLoginParams,
        ) -> Result<OpaqueStartServerLoginResult>;

        fn opaque_finish_server_login(
            params: OpaqueFinishServerLoginParams,
        ) -> Result<OpaqueFinishServerLoginResult>;
    }
}

use opaque_ffi::{
    KeyStretchingFunctionConfig, KeyStretchingFunctionVariant,
    OpaqueCreateServerRegistrationResponseParams, OpaqueCreateServerRegistrationResponseResult,
    OpaqueFinishClientLoginParams, OpaqueFinishClientLoginResult,
    OpaqueFinishClientRegistrationParams, OpaqueFinishClientRegistrationResult,
    OpaqueFinishServerLoginParams, OpaqueFinishServerLoginResult,
    OpaqueFinishServerRegistrationParams, OpaqueFinishServerRegistrationResult,
    OpaqueStartClientLoginParams, OpaqueStartClientLoginResult,
    OpaqueStartClientRegistrationParams, OpaqueStartClientRegistrationResult,
    OpaqueStartServerLoginParams, OpaqueStartServerLoginResult,
};

fn opaque_create_server_setup() -> Vec<u8> {
    let mut rng: OsRng = OsRng;
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    setup.serialize().to_vec()
}

fn opaque_get_server_public_key(data: &[u8]) -> Result<Vec<u8>, Error> {
    let server_setup = decode_server_setup(data)?;
    let pub_key = server_setup.keypair().public().serialize();
    Ok(pub_key.to_vec())
}

fn opaque_create_server_registration_response(
    params: OpaqueCreateServerRegistrationResponseParams,
) -> Result<OpaqueCreateServerRegistrationResponseResult, Error> {
    let server_setup = decode_server_setup(params.server_setup)?;
    let registration_request_bytes = params.registration_request;
    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &server_setup,
        RegistrationRequest::deserialize(&registration_request_bytes)
            .map_err(from_protocol_error("deserialize registrationRequest"))?,
        params.user_identifier.as_bytes(),
    )
    .map_err(from_protocol_error("start serverRegistration"))?;
    let registration_response_bytes = server_registration_start_result.message.serialize();
    Ok(OpaqueCreateServerRegistrationResponseResult {
        registration_response: registration_response_bytes.to_vec(),
    })
}

fn opaque_finish_server_registration(
    params: OpaqueFinishServerRegistrationParams,
) -> Result<OpaqueFinishServerRegistrationResult, Error> {
    let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(&params.message_bytes)
        .map_err(from_protocol_error("finish serverRegistration"))?;

    let password_file = ServerRegistration::finish(upload);

    Ok(OpaqueFinishServerRegistrationResult {
        password_file: password_file.serialize().to_vec(),
    })
}

fn opaque_start_server_login(
    params: OpaqueStartServerLoginParams,
) -> Result<OpaqueStartServerLoginResult, Error> {
    let server_setup = decode_server_setup(params.server_setup)?;
    let registration_record_bytes = get_optional_bytes(params.registration_record)?;
    let credential_request_bytes = params.start_login_request;

    let mut rng: OsRng = OsRng;

    let registration_record = match registration_record_bytes.as_ref() {
        Some(bytes) => Some(
            ServerRegistration::<DefaultCipherSuite>::deserialize(bytes)
                .map_err(from_protocol_error("deserialize registrationRecord"))?,
        ),
        None => None,
    };

    let server_ident = get_optional_string(params.server_identifier)?;
    let client_ident = get_optional_string(params.client_identifier)?;
    let context = get_optional_string(params.context)?;

    let start_params = ServerLoginParameters {
        identifiers: Identifiers {
            client: client_ident.as_ref().map(|val| val.as_bytes()),
            server: server_ident.as_ref().map(|val| val.as_bytes()),
        },
        context: context.as_ref().map(|val| val.as_bytes()),
    };

    let server_login_start_result = ServerLogin::start(
        &mut rng,
        &server_setup,
        registration_record,
        CredentialRequest::deserialize(&credential_request_bytes)
            .map_err(from_protocol_error("deserialize startLoginRequest"))?,
        params.user_identifier.as_bytes(),
        start_params,
    )
    .map_err(from_protocol_error("start server login"))?;

    let login_response = server_login_start_result.message.serialize();
    let server_login_state = server_login_start_result.state.serialize();

    let result = OpaqueStartServerLoginResult {
        server_login_state: server_login_state.to_vec(),
        login_response: login_response.to_vec(),
    };
    Ok(result)
}

fn opaque_finish_server_login(
    params: OpaqueFinishServerLoginParams,
) -> Result<OpaqueFinishServerLoginResult, Error> {
    let server_ident = get_optional_string(params.server_identifier)?;
    let client_ident = get_optional_string(params.client_identifier)?;
    let context = get_optional_string(params.context)?;

    let finish_params = ServerLoginParameters {
        identifiers: Identifiers {
            client: client_ident.as_ref().map(|val| val.as_bytes()),
            server: server_ident.as_ref().map(|val| val.as_bytes()),
        },
        context: context.as_ref().map(|val| val.as_bytes()),
    };

    let state = ServerLogin::<DefaultCipherSuite>::deserialize(params.server_login_state)
        .map_err(from_protocol_error("deserialize serverLoginState"))?;
    let server_login_finish_result = state
        .finish(
            CredentialFinalization::deserialize(params.finish_login_request)
                .map_err(from_protocol_error("deserialize finishLoginRequest"))?,
            finish_params,
        )
        .map_err(from_protocol_error("finish server login"))?;
    Ok(OpaqueFinishServerLoginResult {
        session_key: server_login_finish_result.session_key.to_vec(),
    })
}

fn decode_server_setup(data: &[u8]) -> Result<ServerSetup<DefaultCipherSuite>, Error> {
    ServerSetup::<DefaultCipherSuite>::deserialize(data)
        .map_err(from_protocol_error("deserialize serverSetup"))
}

fn opaque_start_client_registration(
    params: OpaqueStartClientRegistrationParams,
) -> Result<OpaqueStartClientRegistrationResult, Error> {
    let mut client_rng = OsRng;

    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, params.password)
            .map_err(from_protocol_error("start client registration"))?;

    let result = opaque_ffi::OpaqueStartClientRegistrationResult {
        client_registration_state: client_registration_start_result.state.serialize().to_vec(),
        registration_request: client_registration_start_result
            .message
            .serialize()
            .to_vec(),
    };
    Ok(result)
}

fn get_optional_string(ident: String) -> Result<Option<String>, Error> {
    match ident.len() {
        // 0 length results in None
        0 => Ok(None),

        // Any other length results in Some(ident)
        _ => Ok(Some(ident)),
    }
}

fn get_optional_bytes(data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    match data.len() {
        // 0 bytes becomes None
        0 => Ok(None),

        // Any other length becomes Some
        _ => Ok(Some(data.to_vec())),
    }
}

fn opaque_finish_client_registration(
    params: OpaqueFinishClientRegistrationParams,
) -> Result<OpaqueFinishClientRegistrationResult, Error> {
    let registration_response_bytes = params.registration_response;
    let mut rng: OsRng = OsRng;
    let state =
        ClientRegistration::<DefaultCipherSuite>::deserialize(params.client_registration_state)
            .map_err(from_protocol_error("deserialize clientRegistrationState"))?;

    let server_ident = get_optional_string(params.server_identifier)?;
    let client_ident = get_optional_string(params.client_identifier)?;

    let ksf = get_custom_ksf(Some(params.key_stretching_config))?;
    let finish_params = ClientRegistrationFinishParameters::new(
        Identifiers {
            client: client_ident.as_ref().map(|val| val.as_bytes()),
            server: server_ident.as_ref().map(|val| val.as_bytes()),
        },
        ksf.as_ref(),
    );

    let client_finish_registration_result = state
        .finish(
            &mut rng,
            params.password,
            RegistrationResponse::deserialize(registration_response_bytes)
                .map_err(from_protocol_error("deserialize registrationResponse"))?,
            finish_params,
        )
        .map_err(from_protocol_error("finish client registration"))?;

    let message_bytes = client_finish_registration_result.message.serialize();
    let result = OpaqueFinishClientRegistrationResult {
        registration_record: message_bytes.to_vec(),
        export_key: client_finish_registration_result.export_key.to_vec(),
        server_static_public_key: client_finish_registration_result
            .server_s_pk
            .serialize()
            .to_vec(),
    };
    Ok(result)
}

fn opaque_start_client_login(
    params: OpaqueStartClientLoginParams,
) -> Result<OpaqueStartClientLoginResult, Error> {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, params.password)
            .map_err(from_protocol_error("start clientLogin"))?;

    let result = OpaqueStartClientLoginResult {
        client_login_state: client_login_start_result.state.serialize().to_vec(),
        start_login_request: client_login_start_result.message.serialize().to_vec(),
    };
    Ok(result)
}

fn opaque_finish_client_login(
    params: OpaqueFinishClientLoginParams,
) -> Result<cxx::UniquePtr<OpaqueFinishClientLoginResult>, Error> {
    let mut client_rng = OsRng;
    let credential_response_bytes = params.login_response;
    let state = ClientLogin::<DefaultCipherSuite>::deserialize(params.client_login_state)
        .map_err(from_protocol_error("deserialize clientLoginState"))?;

    let server_ident = get_optional_string(params.server_identifier)?;
    let client_ident = get_optional_string(params.client_identifier)?;
    let context = get_optional_string(params.context)?;

    let ksf = get_custom_ksf(Some(params.key_stretching_config))?;

    let finish_params = ClientLoginFinishParameters::new(
        context.as_ref().map(|val| val.as_bytes()),
        Identifiers {
            client: client_ident.as_ref().map(|val| val.as_bytes()),
            server: server_ident.as_ref().map(|val| val.as_bytes()),
        },
        ksf.as_ref(),
    );

    let result = state.finish(
        &mut client_rng,
        params.password,
        CredentialResponse::deserialize(credential_response_bytes)
            .map_err(from_protocol_error("deserialize loginResponse"))?,
        finish_params,
    );

    if result.is_err() {
        // Client-detected login failure
        return Ok(cxx::UniquePtr::null());
    }
    let client_login_finish_result = result.unwrap();

    let result = OpaqueFinishClientLoginResult {
        finish_login_request: client_login_finish_result.message.serialize().to_vec(),
        session_key: client_login_finish_result.session_key.to_vec(),
        export_key: client_login_finish_result.export_key.to_vec(),
        server_static_public_key: client_login_finish_result.server_s_pk.serialize().to_vec(),
    };

    Ok(cxx::UniquePtr::new(result))
}
