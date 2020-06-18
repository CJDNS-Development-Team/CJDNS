# cjdns-splice - Tools for manipulating and splicing cjdns switch labels.

## Functions

Below in the examples labels are written in the hex form for brevity. For label input/output please see cjdns-entities.

### `splice<L: LabelT>(labels: &[L]) -> Result<L>`
This function takes one or more labels and splices them to create a resulting label.
If you have a peer at `0000.0000.0000.0013` and he has a peer at `0000.0000.0000.0015` which you
want to reach, you can splice a label for reaching him using
`splice(&["0000.0000.0000.0015", "0000.0000.0000.0013"])`. Remember that the arguments should be read
right to left, the first hop is the furthest to the right in the splice function. If the result
of the splicing is too long to fit in a label (`Label::max_bit_size()` bits) then it will return `Err(Error::LabelTooLong)`.

See: [LabelSplicer_splice()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/LabelSplicer.h#L36)

```rust
splice(&["0000.0000.0000.0015", "0000.0000.0000.0013"]); // returns Ok("0000.0000.0000.0153")
```

Splice only works to splice a route if the return route is the same size or smaller. If the return
route is larger then the smaller director in the path must be re-encoded to be the same size as
the return path director. `build_label()` will take care of this automatically.

### `is_one_hop<L: LabelT>(label: L, encoding_scheme: &EncodingScheme) -> Result<bool>`
Tests if a `label` contains only one hop. The second argument is the `encoding_scheme` used by the node which is at the beginning of the path given by the `label`.

See: [EncodingScheme_isOneHop()](https://github.com/cjdelisle/cjdns/blob/77259a49e5bc7ca7bc6dca5bd423e02be563bdc5/switch/EncodingScheme.c#L451)

```rust
is_one_hop("0000.0000.0000.0013", &SCHEMES["v358"]); // returns Ok(true)
is_one_hop("0000.0000.0000.0015", &SCHEMES["v358"]); // returns Ok(true)
is_one_hop("0000.0000.0000.0153", &SCHEMES["v358"]); // returns Ok(false)
```
### `get_encoding_form<L: LabelT>(label: L, scheme: &EncodingScheme) -> Result<EncodingSchemeForm>`
Get the encoding **form** used for the first *director* of the label. Recall an
encoding *scheme* is one or more encoding *forms*.
If the label is not recognized as using the given scheme then it'll return `Err(Error::CannotFindForm)`.

See: [EncodingScheme_getFormNum()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/EncodingScheme.c#L23)

```rust
get_encoding_form("0000.0000.0000.0013", &SCHEMES["v358"]); // returns Ok(EncodingSchemeForm {bit_count: 3, prefix_len: 1, prefix: 0b01})
get_encoding_form("0000.0000.0000.1110", &SCHEMES["v358"]); // returns Ok(EncodingSchemeForm {bit_count: 8, prefix_len: 2, prefix: 0})
```

### `re_encode<L: LabelT>(label: L, scheme: &EncodingScheme, desired_form_num: Option<usize>) -> Result<L>`
This will re-encode a label to the encoding *form* specified by **desired_form_num**.
This may return an error if the encoding form cannot
be detected, you pass an invalid **desired_form_num** or if you try to re-encode the self route
(`0001`). It will also return an error if re-encoding a label will make it too long (more than `Label::max_bit_size()`
bits). If desired_form_num is `None` then it will re-encode the label
into it's *cannonical* form, that is the smallest form which can hold that director.

See: [EncodingScheme_convertLabel()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/EncodingScheme.c#L56)

```rust
re_encode("0000.0000.0000.0015", &SCHEMES["v358"], Some(0)); // returns Ok("0000.0000.0000.0015")
re_encode("0000.0000.0000.0015", &SCHEMES["v358"], Some(1)); // returns Ok("0000.0000.0000.0086")
re_encode("0000.0000.0000.0015", &SCHEMES["v358"], Some(2)); // returns Ok("0000.0000.0000.0404")
re_encode("0000.0000.0000.0404", &SCHEMES["v358"], None); // returns Ok("0000.0000.0000.0015")
```

### `build_label<L: LabelT>(path_hops: &[PathHop<L>]) -> Result<(L, Vec<L>)>`
This will construct a label using an array representation of a path.
If any label along the path needs to be re-encoded, it will be.
Each element in the array represents a hop (node) in the path and they each of them has `PathHop.label_p` and/or `PathHop.label_n` depending on whether there is a previous and/or next hop.
`PathHop.label_p` is necessary to know the width of the inverse path hop so that the label can be re-encoded if necessary.

```rust
build_label(&[
    PathHop::new("0000.0000.0000.0000", "0000.0000.0000.0015", &SCHEMES["v358"]),
    PathHop::new("0000.0000.0000.009e", "0000.0000.0000.008e", &SCHEMES["v358"]),
    PathHop::new("0000.0000.0000.0013", "0000.0000.0000.00a2", &SCHEMES["v358"]),
    PathHop::new("0000.0000.0000.001b", "0000.0000.0000.001d", &SCHEMES["v358"]),
    PathHop::new("0000.0000.0000.00ee", "0000.0000.0000.001b", &SCHEMES["v358"]),
    PathHop::new("0000.0000.0000.0019", "0000.0000.0000.001b", &SCHEMES["v358"]),
    PathHop::new("0000.0000.0000.0013", "0000.0000.0000.0000", &SCHEMES["v358"]),
]);
/*
results in (
    "0000.0003.64b5.10e5",
    vec![
        "0000.0000.0000.0015",
        "0000.0000.0000.008e",
        "0000.0000.0000.00a2",
        "0000.0000.0000.001d",
        "0000.0000.0000.0092",
        "0000.0000.0000.001b"
    ]
)
*/
```
This function results in a tuple containing 2 elements, `label` and `path`. `label` is the final label for this `path`. And `path` is the hops to get there.
Notice the second to last hop in the `path` has been changed from 001b to 0092. This is a re-encoding to ensure that the `label` remains the right length as the reverse path for this hop is 00ee which is longer than 001b.

### `routes_through<L: LabelT>(destination: L, mid_path: L) -> Result<bool>`
This will return `Ok(true)` if the node at the end of the route given by `mid_path` is a hop along the path given by `destination`.

See: [LabelSplicer_routesThrough()](https://github.com/cjdelisle/cjdns/blob/cjdns-v20.2/switch/LabelSplicer.h#L52)

```rust
routes_through("0000.001b.0535.10e5", "0000.0000.0000.0015"); // returns Ok(true)
routes_through("0000.001b.0535.10e5", "0000.0000.0000.0013"); // returns Ok(false)
```

### `unsplice<L: LabelT>(destination: L, mid_path: L) -> Result<L>`
This will output a value which if passed to `splice` with the input `mid_path`, would yield the input `destination`.
If `routes_through(destination, mid_path)` would return `Ok(false)`, this returns an `Err(Error::CannotUnsplice)`.

See: [LabelSplicer_unsplice()](https://github.com/cjdelisle/cjdns/blob/77259a49e5bc7ca7bc6dca5bd423e02be563bdc5/switch/LabelSplicer.h#L31)

```rust
splice("0000.0000.0000.0015", "0000.0000.0000.0013"); // returns Ok("0000.0000.0000.0153")
unsplice("0000.0000.0000.0153", "0000.0000.0000.0013"); // returns Ok("0000.0000.0000.0015")
```

