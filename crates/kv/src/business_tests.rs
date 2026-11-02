use super::*;

#[tokio::test]
#[ignore = "requires explicit isolated Redis URLs and ACL administration"]
async fn business_acl_preflight() {
    let url = std::env::var("CAP_TEST_REDIS_URL").expect("isolated Redis");
    assert_eq!(std::env::var("REDIS_URL").unwrap(), url);
    let kv = Kv::connect_redis(&url).await.unwrap();
    let id = format!("business-acl-{}-{}", std::process::id(), now_ms());
    let keys: Vec<String> = (0..5).map(|i| format!("{id}:{i}")).collect();
    let now = now_ms();
    let mut args = vec![String::new(); 10];
    args[0] = "issue".into();
    args[1] = "fp".into();
    args[2] = format!(
        "{{\"typ\":\"cap-business\",\"v\":1,\"iat\":{now},\"exp\":{}}}",
        now + 60000
    );
    args[3] = "credential".into();
    args[4] = now.to_string();
    args[5] = (now + 60000).to_string();
    kv.business_transition(&keys[..1], &args).await.unwrap();
    let mut admin = kv.conn.clone();
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&id)
        .arg("on")
        .arg(">test-password")
        .arg(format!("~{id}:*"))
        .arg("+@all")
        .arg("-set")
        .query_async::<()>(&mut admin)
        .await
        .unwrap();
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut restricted = client.get_multiplexed_async_connection().await.unwrap();
    redis::cmd("AUTH")
        .arg(&id)
        .arg("test-password")
        .query_async::<()>(&mut restricted)
        .await
        .unwrap();
    args[0] = "complete".into();
    args[6] = "result".into();
    args[7] = "{}".into();
    args[8] = (now + 60000).to_string();
    args[9] = "60000".into();
    let denied = redis::Script::new(include_str!("business.lua"))
        .key(&keys)
        .arg(&args)
        .invoke_async::<Vec<String>>(&mut restricted)
        .await;
    assert!(denied.is_err());
    for key in &keys[1..] {
        assert!(!kv.exists(key).await.unwrap());
    }
    assert_eq!(
        kv.hget(&keys[0], "state").await.unwrap().as_deref(),
        Some("issued")
    );
    // Drop the TCP connection after just the first reply byte, before any
    // application can decode the commit outcome. The state must not reset.
    {
        use std::io::{Read, Write};
        let redis::ConnectionAddr::Tcp(host, port) = &client.get_connection_info().addr else {
            panic!("isolated test requires plain TCP Redis");
        };
        let mut socket = std::net::TcpStream::connect((host.as_str(), *port)).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let info = &client.get_connection_info().redis;
        let mut setup = Vec::new();
        if let Some(password) = &info.password {
            let mut auth = redis::cmd("AUTH");
            if let Some(username) = &info.username {
                auth.arg(username);
            }
            auth.arg(password);
            setup.push(auth);
        }
        let mut select = redis::cmd("SELECT");
        select.arg(info.db);
        setup.push(select);
        for command in setup {
            socket.write_all(&command.get_packed_command()).unwrap();
            let mut reply = [0; 5];
            socket.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"+OK\r\n", "Redis connection initialization failed");
        }
        let mut command = redis::cmd("EVAL");
        command
            .arg(include_str!("business.lua"))
            .arg(keys.len())
            .arg(&keys)
            .arg(&args);
        socket.write_all(&command.get_packed_command()).unwrap();
        let mut first = [0];
        socket.read_exact(&mut first).unwrap();
        assert_eq!(first[0], b'*');
    }
    assert_eq!(
        kv.business_transition(&keys, &args).await.unwrap(),
        vec!["used"]
    );
    args[0] = "consume".into();
    // Deny the final DEL: preflight must protect the authority from mutation.
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&id)
        .arg("+set")
        .arg("-del")
        .query_async::<()>(&mut admin)
        .await
        .unwrap();
    assert!(
        redis::Script::new(include_str!("business.lua"))
            .key(&keys)
            .arg(&args)
            .invoke_async::<Vec<String>>(&mut restricted)
            .await
            .is_err()
    );
    assert_eq!(
        kv.hget(&keys[0], "state").await.unwrap().as_deref(),
        Some("solved")
    );
    assert_eq!(kv.business_transition(&keys, &args).await.unwrap()[0], "ok");
    // Distinct challenges and result tokens compete for ONE issued business.
    let mut left: Vec<String> = (0..5).map(|i| format!("{id}:left:{i}")).collect();
    let mut right: Vec<String> = (0..5).map(|i| format!("{id}:right:{i}")).collect();
    right[0] = left[0].clone();
    args[0] = "issue".into();
    kv.business_transition(&left[..1], &args).await.unwrap();
    let ttl: i64 = redis::cmd("PTTL")
        .arg(&left[0])
        .query_async(&mut admin)
        .await
        .unwrap();
    assert!((86_390_000..=86_400_000).contains(&ttl));
    args[0] = "complete".into();
    let mut other_args = args.clone();
    other_args[6] = "other-result".into();
    let (a, b) = tokio::join!(
        kv.business_transition(&left, &args),
        kv.business_transition(&right, &other_args)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(usize::from(a[0] == "ok") + usize::from(b[0] == "ok"), 1);
    let loser = if a[0] == "ok" { &right } else { &left };
    for key in &loser[1..] {
        assert!(!kv.exists(key).await.unwrap());
    }
    left.extend(right);
    kv.del_many(&left).await.unwrap();
    kv.del_many(&keys).await.unwrap();
    redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&id)
        .query_async::<i64>(&mut admin)
        .await
        .unwrap();
}
