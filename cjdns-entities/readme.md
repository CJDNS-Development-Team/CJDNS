# cjdns-entities - entities operated by CJDNS.

## Traits

### `LabelBits`

Trait for a routing label's internal data type. Routing labels itself are opaque, so this trait is required for internal data manipulations.

The following parent traits of `LabelBits` are considered public: `Sized`, `Copy`, `Eq`, `From<u32>`, `Display`.

For label manipulation routines please see the [cjdns-splice](../cjdns-splice/readme.md) crate.

This trait implemented for `u64` and `u128`.

## Type aliases

### `DefaultRoutingLabel`

A 64 bit routing label.

## Types

### `RoutingLabel`

Routing label. 

For more information on labels please refer to [the whitepaper](https://github.com/cjdelisle/cjdns/blob/master/doc/Whitepaper.md#definitions).

### `EncodingSchemeForm`

A form of an encoding scheme. Form is used as follows to encode a director:

```
[     director     ] [     form.prefix     ]
^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^
form.bit_count bits   form.prefix_len bits
```

### `EncodingScheme`

An iterable list of scheme forms. Schemes are comparable for equality, immutable, opaque.

## Fields

### `SCHEMES`

A lazy static `HashMap` of schemes indexed by name.

#### `&SCHEMES["v358"]`

The encoding scheme consisting of 3, 5 or 8 bit data spaces, this encoding scheme is special
because it encodes strangely (a bug) and thus conversion from one form to another is non-standard.
