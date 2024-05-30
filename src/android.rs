#![cfg(target_os = "android")]

use crate::{
    args::ArgProxy,
    error::{Error, Result},
    Args,
};
use jni::{
    objects::{JClass, JString},
    sys::{jchar, jint},
    JNIEnv,
};

/// # Safety
///
/// Running tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_run(
    mut env: JNIEnv,
    _clazz: JClass,
    proxy_url: JString,
    tun_fd: jint,
    tun_mtu: jchar,
    verbosity: jint,
    dns_strategy: jint,
) -> jint {
    let dns = dns_strategy.try_into().unwrap();
    let verbosity = verbosity.try_into().unwrap();
    let filter_str = &format!("off,tun2proxy={verbosity}");
    let filter = android_logger::FilterBuilder::new().parse(filter_str).build();
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tun2proxy")
            .with_max_level(log::LevelFilter::Trace)
            .with_filter(filter),
    );
    let proxy_url = get_java_string(&mut env, &proxy_url).unwrap();
    let proxy = ArgProxy::try_from(proxy_url.as_str()).unwrap();

    let mut args = Args::default();
    args.proxy(proxy).tun_fd(Some(tun_fd)).dns(dns).verbosity(verbosity);
    crate::mobile_api::mobile_run(args, tun_mtu, false)
}

/// # Safety
///
/// Shutdown tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_stop(_env: JNIEnv, _: JClass) -> jint {
    crate::mobile_api::mobile_stop()
}

fn get_java_string(env: &mut JNIEnv, string: &JString) -> Result<String, Error> {
    Ok(env.get_string(string)?.into())
}
