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
