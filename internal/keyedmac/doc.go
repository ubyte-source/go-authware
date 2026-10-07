// Package keyedmac computes the HMAC of one key: a [MAC] keeps the keyed
// states of its hash in a pool, so a sum that reuses one costs no key schedule,
// and appends to room the caller owns.
package keyedmac
