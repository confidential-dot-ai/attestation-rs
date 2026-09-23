//! Section 4.10: one JSON encoding per value. serde's defaults admit others,
//! each of which would let two implementations disagree about an envelope or
//! a policy: `null` for an absent optional member, a JSON array for a struct
//! (its fields in order), and `{"variant": null}` for a unit enum. `present`
//! closes the first on each optional member; `from_slice` closes the other
//! two for everything it parses, streaming, at every depth.

use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::Deserialize;
use std::fmt;

/// `deserialize_with` for an optional member: present means a value.
pub fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// Parses one JSON value from `json` into `T`, reading structs only from
/// objects and enums only from strings, and refusing trailing data.
pub fn from_slice<'de, T: Deserialize<'de>>(json: &'de [u8]) -> serde_json::Result<T> {
    let mut de = serde_json::Deserializer::from_slice(json);
    let value = T::deserialize(Strict(&mut de))?;
    de.end()?;
    Ok(value)
}

/// A deserializer that hands `Strict` to everything nested in it.
struct Strict<D>(D);

macro_rules! forward {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.0.$method(Wrap(visitor))
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Strict<D> {
    type Error = D::Error;

    forward! {
        deserialize_any deserialize_bool deserialize_i8 deserialize_i16 deserialize_i32
        deserialize_i64 deserialize_i128 deserialize_u8 deserialize_u16 deserialize_u32
        deserialize_u64 deserialize_u128 deserialize_f32 deserialize_f64 deserialize_char
        deserialize_str deserialize_string deserialize_bytes deserialize_byte_buf
        deserialize_option deserialize_unit deserialize_seq deserialize_map
        deserialize_identifier deserialize_ignored_any
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_unit_struct(name, Wrap(visitor))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_newtype_struct(name, Wrap(visitor))
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_tuple(len, Wrap(visitor))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_tuple_struct(name, len, Wrap(visitor))
    }

    /// A struct is an object; an array of its fields is refused.
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_map(Wrap(visitor))
    }

    /// An enum is the string naming its variant.
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_str(Variant(visitor))
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

/// A visitor whose nested deserializers are `Strict`.
struct Wrap<V>(V);

impl<'de, V: Visitor<'de>> Visitor<'de> for Wrap<V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.expecting(f)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<V::Value, E> {
        self.0.visit_bool(v)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<V::Value, E> {
        self.0.visit_i64(v)
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<V::Value, E> {
        self.0.visit_i128(v)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<V::Value, E> {
        self.0.visit_u64(v)
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<V::Value, E> {
        self.0.visit_u128(v)
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<V::Value, E> {
        self.0.visit_f64(v)
    }
    fn visit_char<E: de::Error>(self, v: char) -> Result<V::Value, E> {
        self.0.visit_char(v)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<V::Value, E> {
        self.0.visit_str(v)
    }
    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<V::Value, E> {
        self.0.visit_borrowed_str(v)
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<V::Value, E> {
        self.0.visit_string(v)
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<V::Value, E> {
        self.0.visit_bytes(v)
    }
    fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<V::Value, E> {
        self.0.visit_borrowed_bytes(v)
    }
    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<V::Value, E> {
        self.0.visit_byte_buf(v)
    }
    fn visit_none<E: de::Error>(self) -> Result<V::Value, E> {
        self.0.visit_none()
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<V::Value, D::Error> {
        self.0.visit_some(Strict(d))
    }
    fn visit_unit<E: de::Error>(self) -> Result<V::Value, E> {
        self.0.visit_unit()
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<V::Value, D::Error> {
        self.0.visit_newtype_struct(Strict(d))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
        self.0.visit_seq(Seq(seq))
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
        self.0.visit_map(Map(map))
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<V::Value, A::Error> {
        self.0.visit_enum(Enum(data))
    }
}

/// Reads an enum from the string naming its variant.
struct Variant<V>(V);

impl<'de, V: Visitor<'de>> Visitor<'de> for Variant<V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.expecting(f)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<V::Value, E> {
        self.0.visit_enum(v.into_deserializer())
    }
    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<V::Value, E> {
        self.0
            .visit_enum(de::value::BorrowedStrDeserializer::new(v))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<V::Value, E> {
        self.0.visit_enum(v.into_deserializer())
    }
}

struct Seq<A>(A);

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Seq<A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, A::Error> {
        self.0.next_element_seed(Seed(seed))
    }
    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

struct Map<A>(A);

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Map<A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        self.0.next_key_seed(Seed(seed))
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, A::Error> {
        self.0.next_value_seed(Seed(seed))
    }
    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

struct Seed<S>(S);

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<S::Value, D::Error> {
        self.0.deserialize(Strict(d))
    }
}

struct Enum<A>(A);

impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for Enum<A> {
    type Error = A::Error;
    type Variant = VariantData<A::Variant>;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), A::Error> {
        self.0
            .variant_seed(Seed(seed))
            .map(|(v, rest)| (v, VariantData(rest)))
    }
}

struct VariantData<A>(A);

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for VariantData<A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), A::Error> {
        self.0.unit_variant()
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, A::Error> {
        self.0.newtype_variant_seed(Seed(seed))
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.0.tuple_variant(len, Wrap(visitor))
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.0.struct_variant(fields, Wrap(visitor))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct S {
        #[serde(default, deserialize_with = "super::present")]
        a: Option<u8>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "kebab-case")]
    enum E {
        OneThing,
        Other,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Outer {
        inner: Inner,
        list: Vec<Inner>,
        e: E,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields, default)]
    struct Inner {
        n: u8,
    }

    impl Default for Inner {
        fn default() -> Self {
            Inner { n: 7 }
        }
    }

    #[test]
    fn one_encoding_per_value() {
        let good = br#"{"inner":{"n":1},"list":[{}],"e":"one-thing"}"#;
        let parsed: Outer = super::from_slice(good).unwrap();
        assert_eq!(
            parsed,
            Outer {
                inner: Inner { n: 1 },
                list: vec![Inner { n: 7 }],
                e: E::OneThing
            }
        );
        // serde's defaults take each of these second encodings; ours do not.
        for (bad, why) in [
            (
                &br#"{"inner":[1],"list":[],"e":"other"}"#[..],
                "a struct as its fields in order",
            ),
            (
                br#"{"inner":[],"list":[],"e":"other"}"#,
                "an empty array for a defaulted struct",
            ),
            (
                br#"{"inner":{},"list":[[]],"e":"other"}"#,
                "a struct in a list",
            ),
            (
                br#"{"inner":{},"list":[],"e":{"other":null}}"#,
                "a unit enum as a map",
            ),
        ] {
            assert!(
                serde_json::from_slice::<Outer>(bad).is_ok(),
                "serde takes {why}"
            );
            assert!(super::from_slice::<Outer>(bad).is_err(), "{why}");
        }
        assert!(super::from_slice::<Outer>(br#"{"inner":{},"list":[],"e":"other"} {}"#).is_err());
    }

    #[test]
    fn null_is_not_absent() {
        assert_eq!(serde_json::from_str::<S>("{}").unwrap(), S { a: None });
        assert_eq!(
            serde_json::from_str::<S>(r#"{"a":1}"#).unwrap(),
            S { a: Some(1) }
        );
        assert!(serde_json::from_str::<S>(r#"{"a":null}"#).is_err());
    }
}
