/*
 * Wrapper header for bindgen — pulls in all Heimdal headers needed
 * by the heimdal-pkinit Rust adapter.
 */

#include <krb5.h>
#include <hx509.h>
#include <hdb.h>
#include <kdc.h>
#include <pkinit_asn1.h>
#include <rfc2459_asn1.h>
#include <cms_asn1.h>
#include <heim_asn1.h>
#include <der.h>
#include <der-protos.h>
