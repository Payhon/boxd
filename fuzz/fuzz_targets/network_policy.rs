#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use box_egress::{
    CustomNetworkPolicy, DomainPattern, IpCidr, evaluate_custom_dns_answer,
    evaluate_custom_tcp_connect,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 8 * 1024;

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(253).collect()
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT)];
    let chunks: Vec<String> = input.chunks(256).take(64).map(text).collect();
    let domains = chunks.iter().take(16).cloned().collect::<Vec<_>>();
    let cidrs = chunks.iter().skip(16).take(16).cloned().collect::<Vec<_>>();
    let denied = chunks.iter().skip(32).take(16).cloned().collect::<Vec<_>>();

    for value in &domains {
        let _ = DomainPattern::parse(value);
    }
    for value in &cidrs {
        let _ = IpCidr::parse(value);
    }
    let Ok(policy) = CustomNetworkPolicy::from_strings(domains, cidrs, denied) else {
        return;
    };
    let hostname = text(input);
    let address = IpAddr::V4(Ipv4Addr::new(
        input.first().copied().unwrap_or_default(),
        input.get(1).copied().unwrap_or_default(),
        input.get(2).copied().unwrap_or_default(),
        input.get(3).copied().unwrap_or_default(),
    ));
    let _ = evaluate_custom_dns_answer(&policy, &hostname, address);
    let _ = evaluate_custom_tcp_connect(&policy, Some(&hostname), address, 80);
    let _ = evaluate_custom_tcp_connect(&policy, None, address, 443);
});
