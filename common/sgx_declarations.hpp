#pragma once

typedef uint8_t GroupId[4];

#define SGX_ECP256_KEY_SIZE             32
#define SGX_NISTP_ECP256_KEY_SIZE       (SGX_ECP256_KEY_SIZE/sizeof(uint32_t))
#define SGX_MAC_SIZE                    16              /* Message Authentication Code - 16 bytes */

struct ec256Key
{
    uint8_t gx[SGX_ECP256_KEY_SIZE];
    uint8_t gy[SGX_ECP256_KEY_SIZE];
};

struct SPIDType
{
    uint8_t id[16];
};

struct ec256Signature
{
    uint32_t x[SGX_NISTP_ECP256_KEY_SIZE];
    uint32_t y[SGX_NISTP_ECP256_KEY_SIZE];
};

typedef uint8_t MacType[SGX_MAC_SIZE];

struct PropertyType
{
    uint8_t  sgx_ps_sec_prop_desc[256];
};

class BaseNameType
{
    uint8_t             name[32];
};

#define SGX_REPORT_BODY_RESERVED1_BYTES 12
#define SGX_REPORT_BODY_RESERVED2_BYTES 32
#define SGX_REPORT_BODY_RESERVED3_BYTES 32
#define SGX_REPORT_BODY_RESERVED4_BYTES 42
#define SGX_CPUSVN_SIZE   16

struct CpuSvnType
{
    uint8_t                        svn[SGX_CPUSVN_SIZE];
};

#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_ISV_FAMILY_ID_SIZE  16
typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];

#define SGX_HASH_SIZE        32              /* SHA256 */

#define SGX_CONFIGID_SIZE 64
typedef uint8_t                    sgx_config_id_t[SGX_CONFIGID_SIZE];

struct sgx_attributes_t
{
    uint64_t      flags;
    uint64_t      xfrm;
} ;

 struct sgx_measurement_t
{
    uint8_t                 m[SGX_HASH_SIZE];
} ;



typedef uint16_t            sgx_prod_id_t;
typedef uint16_t                   sgx_isv_svn_t;

#define SGX_REPORT_DATA_SIZE    64

struct sgx_report_data_t
{
    uint8_t                 d[SGX_REPORT_DATA_SIZE];
} ;

typedef struct ReportBodyType
{
    CpuSvnType           cpu_svn;        /* (  0) Security Version of the CPU */
    uint32_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
    uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
    sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
    sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
    sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
    uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
    sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
    uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
    sgx_config_id_t         config_id;      /* (192) CONFIGID */
    uint16_t           isv_prod_id;    /* (256) Product ID of the Enclave */
    uint16_t           isv_svn;        /* (258) Security Version of the Enclave */
    uint16_t        config_svn;     /* (260) CONFIGSVN */
    uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
    sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
    sgx_report_data_t       report_data;    /* (320) Data provided by the user */
} sgx_report_body_t;


struct QuoteType
{
    uint16_t            version;        /* 0   */
    uint16_t            sign_type;      /* 2   */
    GroupId             epid_group_id;  /* 4   */
    uint16_t            qe_svn;         /* 8   */
    uint16_t            pce_svn;        /* 10  */
    uint16_t            xeid;           /* 12  */
    BaseNameType        basename;       /* 16  */
    ReportBodyType      report_body;    /* 48  */
    uint32_t            signature_len;  /* 432 */
    uint8_t             signature[];    /* 436 */
};

struct Msg2Type
{
    ec256Key g_b;         /* the Endian-ness of Gb is Little-Endian */
    SPIDType spid;
    uint16_t quote_type;  /* unlinkable Quote(0) or linkable Quote(1) in little endian*/
    uint16_t kdf_id;      /* key derivation function id in little endian. */
    ec256Signature sign_gb_ga;  /* In little endian */
    MacType mac;         /* mac_smk(g_b||spid||quote_type||kdf_id||sign_gb_ga) */
    uint32_t sig_rl_size;
    uint8_t sig_rl[];
};

class Msg3Type
{
    MacType                mac;         /* mac_smk(g_a||ps_sec_prop||quote) */
    ec256Key       g_a;         /* the Endian-ness of Ga is Little-Endian */
    PropertyType   ps_sec_prop; /* reserved Must be 0 */
    uint8_t                  quote[];
};