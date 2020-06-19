# cjdns-entities - entities operated by CJDNS.

## Traits

### `LabelT`

Trait for a label. Labels are opaque, however some traits are added for internal manipulation by other crates.

The following parent traits of `LabelT` are considered public: `Sized`, `Copy`, `Eq`, `PartialEq`, `ToString`.

The following functions of `LabelT` are considered public: `to_bit_string`.

For label manipulation routines please see the [cjdns-splice](../cjdns-splice/readme.md) crate.

For more information on labels please see [the whitepaper](https://github.com/cjdelisle/cjdns/blob/master/doc/Whitepaper.md#definitions).

## Types

### `Label`

Default type for labels, a synonym for `Label64`.

## Structs

### `Label64`

A 64 bit label. Can be constructed from `u64` and `&str`.

### `Label128`

A 128 bit label. Can be constructed the same ways as `Label64` - from `u128` and `&str`.

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
