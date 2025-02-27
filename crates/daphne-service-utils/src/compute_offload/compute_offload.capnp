# Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

@0xd932f3d934afce3b;

using Base = import "../capnproto/base.capnp";

using VdafConfig = Text; # json encoded
using VdafVerifyKey = Base.U8L32;

struct TimeRange @0xf0d27aaa9b1959f7 {
    start @0 :UInt64;
    end @1 :UInt64;
}

# Top level message
struct InitializeReports @0x90aadb2f44c9fb78 {
    hpkeKeys         @0 :List(HpkeReceiverConfig);
    validReportRange @1 :TimeRange;
    taskId           @2 :Base.TaskId;
    taskConfig       @3 :PartialDapTaskConfig;
    aggParam         @4 :Data; # encoded
    prepInits        @5 :List(PrepareInit);
}

struct HpkeReceiverConfig @0xeec9b4a50458edb7 {
    struct HpkeConfig @0xa546066418a5cdc7 {
        enum HpkeKemId @0xf4bbeaed8d1fd18a {
            p256HkdfSha256 @0; x25519HkdfSha256 @1;
        }
        enum HpkeKdfId @0x9336afc63df27ba3 { hkdfSha256 @0; }
        enum HpkeAeadId @0xd68d403e118c806c { aes128Gcm @0; }

        id @0 :UInt8;
        kemId @1 :HpkeKemId;
        kdfId @2 :HpkeKdfId;
        aeadId @3 :HpkeAeadId;
        publicKey @4 :Data;
    }

    config @0 :HpkeConfig;
    privateKey @1 :Data;
}

struct PartialDapTaskConfig @0xb11c76132b15968a {

    version             @0  :Base.DapVersion;
    methodIsTaskprov    @1  :Bool;
    notBefore           @2  :Base.Time;
    notAfter            @3  :Base.Time;
    vdaf                @4  :VdafConfig;
    vdafVerifyKey       @5  :VdafVerifyKey;
}

struct PublicExtensionsList @0x8b3c98c0ddd0043e {

    union {
	# Each extension is encoded according to the DAP spec in
	# tag-length-value form.
        list @0 :List(Data);

	# draft09 compatibility: Previously DAP had no extensions in the
	# report.
	none @1 :Void;
    }
}

struct ReportMetadata @0xefba178ad4584bc4 {

    id               @0 :Base.ReportId;
    time             @1 :Base.Time;
    publicExtensions @2 :PublicExtensionsList;
}

struct PrepareInit @0x8192568cb3d03f59 {

    struct HpkeCiphertext @0xf0813319decf7eaf {
        configId @0 :UInt8;
        enc      @1 :Data;
        payload  @2 :Data;
    }

    struct ReportShare @0xb4134aa2db41ef60 {
        reportMetadata      @0 :ReportMetadata;
        publicShare         @1 :Data;
        encryptedInputShare @2 :HpkeCiphertext;
    }

    reportShare @0 :ReportShare;
    payload     @1 :Data;
}



struct InitializedReports @0xf36341397ae4a146 {
    struct InitializedReport @0xfa833aa6b5d03d6d {
        using VdafPrepShare = Data;
        using VdafPrepState = Data;

        union {
            ready :group {
                metadata @0 :ReportMetadata;
                publicShare @1 :Data;
                prepShare @2 :VdafPrepShare;
                prepState @3 :VdafPrepState;
                peerPrepShare @4 :Data;
            }
            rejected :group {
                metadata @5 :ReportMetadata;
                failure @6 :Base.ReportError;
            }
        }
    }

    vdafConfig @0 :VdafConfig;
    reports @1 :List(InitializedReport);
}
