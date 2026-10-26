use super::*;
use crate::self_test::{SelfTest, st_assert, st_assert_eq};
use moto_sdk::sys_io::api_ip_device::Cidr;

pub(crate) const TESTS: &[SelfTest] = &[(
    "net::registration::quota_routes_and_vacant_slots",
    quota_routes_and_vacant_slots,
)];

fn config(n: u8) -> Registration {
    Registration {
        name: format!("wg{n}"),
        mtu: 1420,
        addresses: vec![Cidr {
            address: std::net::Ipv4Addr::new(10, 50, n, 1).into(),
            prefix_len: 32,
        }],
        routes: vec![Cidr {
            address: std::net::Ipv4Addr::new(10, 60, n, 0).into(),
            prefix_len: 24,
        }],
    }
}

fn quota_routes_and_vacant_slots() -> std::result::Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let runtime = super::super::self_test::runtime()?;
        let boot = super::super::self_test::add_device(&runtime, "boot", "127.0.0.1/8");
        let first = runtime
            .register_packet_device(config(0))
            .await
            .map_err(|e| e.to_string())?
            .0;
        for bad in [
            config(0),
            Registration {
                name: "other".into(),
                ..config(0)
            },
            Registration {
                routes: config(0).routes,
                ..config(1)
            },
        ] {
            st_assert!(runtime.register_packet_device(bad).await.is_err());
            st_assert_eq!(runtime.inner.borrow().devices.slot_count(), 2);
        }
        let mut indices = vec![first];
        for n in 1..4 {
            indices.push(runtime.register_packet_device(config(n)).await.unwrap().0);
        }
        st_assert_eq!(runtime.inner.borrow().devices.packet_count(), 4);
        st_assert!(runtime.register_packet_device(config(4)).await.is_err());
        st_assert_eq!(runtime.inner.borrow().devices.slot_count(), 5);
        runtime.remove_device(indices[1]).await;
        st_assert!(runtime.inner.borrow().devices.get(indices[1]).is_none());
        let replacement = runtime.register_packet_device(config(1)).await.unwrap().0;
        st_assert_eq!(replacement, 5);
        st_assert!(runtime.inner.borrow().devices.get(boot).is_some());
        st_assert_eq!(
            runtime.find_route(&"10.60.0.8".parse().unwrap()).unwrap().0,
            first
        );
        for index in [first, indices[2], indices[3], replacement] {
            runtime.remove_device(index).await;
        }
        st_assert_eq!(runtime.inner.borrow().devices.packet_count(), 0);
        st_assert_eq!(runtime.stats.num_devices.get(), 1);
        let mut broad = config(0);
        broad.routes[0] = Cidr {
            address: "0.0.0.0".parse().unwrap(),
            prefix_len: 0,
        };
        let broad = runtime.register_packet_device(broad).await.unwrap().0;
        let narrow = runtime.register_packet_device(config(1)).await.unwrap().0;
        st_assert_eq!(
            runtime.find_route(&"10.60.1.8".parse().unwrap()).unwrap().0,
            narrow
        );
        st_assert_eq!(
            runtime.find_route(&"192.0.2.1".parse().unwrap()).unwrap().0,
            broad
        );
        runtime.remove_device(narrow).await;
        runtime.remove_device(broad).await;
        runtime.remove_device(boot).await;
        st_assert_eq!(runtime.stats.num_devices.get(), 0);
        Ok(())
    })
}
