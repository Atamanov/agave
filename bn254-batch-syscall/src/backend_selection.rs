#[cfg(all(
    not(target_os = "solana"),
    any(
        all(
            feature = "backend-b1-arkworks",
            feature = "backend-b2-arkworks-optimized"
        ),
        all(feature = "backend-b1-arkworks", feature = "backend-b3-mcl"),
        all(feature = "backend-b1-arkworks", feature = "backend-b4-helios"),
        all(feature = "backend-b1-arkworks", feature = "backend-b5-helios-ifma"),
        all(feature = "backend-b2-arkworks-optimized", feature = "backend-b3-mcl"),
        all(
            feature = "backend-b2-arkworks-optimized",
            feature = "backend-b4-helios"
        ),
        all(
            feature = "backend-b2-arkworks-optimized",
            feature = "backend-b5-helios-ifma"
        ),
        all(feature = "backend-b3-mcl", feature = "backend-b4-helios"),
        all(feature = "backend-b3-mcl", feature = "backend-b5-helios-ifma"),
        all(feature = "backend-b4-helios", feature = "backend-b5-helios-ifma")
    )
))]
compile_error!("select exactly one BN254 native backend");
