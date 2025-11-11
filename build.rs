use quote::{ToTokens, quote};
use std::{env, fs, path::Path};
use syn::{ExprPath, ExprStruct, FieldsNamed, Ident, Item, ItemEnum, ItemMod, ItemStruct, Meta, Type, TypePath, fold::Fold, parse_quote};
use typify::{TypeSpace, TypeSpaceSettings};

/// Replaces definitions and references of controltype-specific types (such as `FrbcActuatorStatus`) with the a shortened name (e.g. `ActuatorStatus`, which should be places in the `frbc` module).
struct ReplaceTypeDefinitions;

fn replace_prefix(s: &str) -> String {
    s.replace("Pebc", "")
        .replace("Ppbc", "")
        .replace("Ombc", "")
        .replace("Frbc", "")
        .replace("Ddbc", "")
}

impl Fold for ReplaceTypeDefinitions {
    fn fold_type_path(&mut self, mut type_path: TypePath) -> TypePath {
        let type_ident = &mut type_path.path.segments.last_mut().unwrap().ident;
        *type_ident = Ident::new(&replace_prefix(&type_ident.to_string()), type_ident.span());
        syn::fold::fold_type_path(self, type_path)
    }

    fn fold_item_struct(&mut self, mut item_struct: ItemStruct) -> ItemStruct {
        item_struct.ident = Ident::new(&replace_prefix(&item_struct.ident.to_string()), item_struct.ident.span());
        syn::fold::fold_item_struct(self, item_struct)
    }

    fn fold_item_enum(&mut self, mut item_enum: ItemEnum) -> ItemEnum {
        item_enum.ident = Ident::new(&replace_prefix(&item_enum.ident.to_string()), item_enum.ident.span());
        syn::fold::fold_item_enum(self, item_enum)
    }

    fn fold_expr_path(&mut self, mut expr_path: ExprPath) -> ExprPath {
        let type_ident = &mut expr_path.path.segments.last_mut().unwrap().ident;
        *type_ident = Ident::new(&replace_prefix(&type_ident.to_string()), type_ident.span());
        syn::fold::fold_expr_path(self, expr_path)
    }

    fn fold_expr_struct(&mut self, mut expr_struct: ExprStruct) -> ExprStruct {
        let ident = &mut expr_struct.path.segments.last_mut().unwrap().ident;
        *ident = Ident::new(&replace_prefix(&ident.to_string()), ident.span());
        syn::fold::fold_expr_struct(self, expr_struct)
    }
}

/// Replaces references to controltype-specific types (such as `FrbcActuatorStatus`) with the fully qualified path (e.g. `crate::frbc::ActuatorStatus`).
struct ReplaceTypeReferences;

impl Fold for ReplaceTypeReferences {
    fn fold_type_path(&mut self, mut type_path: TypePath) -> TypePath {
        let type_ident = &mut type_path.path.segments.last_mut().unwrap().ident;
        let type_ident_str = type_ident.to_string();
        if type_ident_str.starts_with("Pebc")
            || type_ident_str.starts_with("Ppbc")
            || type_ident_str.starts_with("Ombc")
            || type_ident_str.starts_with("Frbc")
            || type_ident_str.starts_with("Ddbc")
        {
            let (module_ident, short_type_ident) = type_ident_str.split_at(4);
            let short_type_ident = Ident::new(short_type_ident, type_ident.span());
            let module_ident = Ident::new(&module_ident.to_lowercase(), type_ident.span());
            syn::fold::fold_type_path(self, parse_quote!(crate::#module_ident::#short_type_ident))
        } else {
            syn::fold::fold_type_path(self, type_path)
        }
    }
}

/// Removes the `message_type` field from struct definitions, because it'll be used as a discriminator in `Message`.
struct RemoveMessageType;

impl Fold for RemoveMessageType {
    fn fold_fields_named(&mut self, mut fields: FieldsNamed) -> FieldsNamed {
        fields.named = fields
            .named
            .into_pairs()
            .filter(|pair| {
                let Some(ident) = &pair.value().ident else { return true };
                ident != "message_type"
            })
            .collect();
        syn::fold::fold_fields_named(self, fields)
    }
}

/// `typify` generates an error type for conversion errors, which is located in `crate:error`.
/// This adjusts references to conversion errors to point there.
struct ReplaceGeneratedErrorPath;

impl Fold for ReplaceGeneratedErrorPath {
    fn fold_type_path(&mut self, mut type_path: syn::TypePath) -> syn::TypePath {
        let type_ident = &mut type_path.path.segments.last_mut().unwrap().ident;
        if type_ident == "ConversionError" {
            syn::fold::fold_type_path(self, parse_quote!(crate::error::ConversionError))
        } else {
            syn::fold::fold_type_path(self, type_path)
        }
    }
}

fn main() {
    let content = std::fs::read_to_string("./src/s2.schema.json").expect("Error reading JSON schema");
    let schema = serde_json::from_str::<schemars::schema::RootSchema>(&content).expect("Error parsing JSON schema");

    let mut type_space = TypeSpace::new(TypeSpaceSettings::default().with_derive("PartialEq".to_string()));

    type_space
        .add_root_schema(schema)
        .expect("Error adding JSON schema to typify TypeSpace");

    let base_contents = syn::parse2::<syn::File>(type_space.to_stream()).expect("Error parsing typify output");
    // Define the modules and ensure they import the necessary types.
    let mut root_module = quote! {
        /// Returns the version of S2 this library was built with.
        ///
        /// You can use this to check compatibility between your and others' implementations of S2.
        /// When using [`S2Connection::initialize_as_rm`][crate::websockets_json::S2Connection::initialize_as_rm], the version requested by the CEM is checked against this value.
        pub fn s2_schema_version() -> semver::Version {
            semver::Version::parse("0.0.2-beta").expect("Failed to parse S2 schema version; this is a bug in s2energy and should be reported")
        }
    };
    let mut pebc: ItemMod = parse_quote!(
        /// Types specific to the Power Envelope Based Control type.
        ///
        /// Use PEBC for devices of which the power producing or consuming behavior cannot be controlled, but can be limited in some way.
        /// This could, for example, be a curtailable PV installation or an EV charger that can be curtailed.
        ///
        /// For more information on the different control types, see [the S2 documentation website](https://docs.s2standard.org/docs/concepts/control-types/).
        pub mod pebc {
            use crate::common::*;
        }
    );
    let mut ppbc: ItemMod = parse_quote!(
        /// Types specific to the Power Profile Based Control type.
        ///
        /// Use PPBC for devices which have to perform a certain tasks, but which are flexible w.r.t when this task can be executed.
        /// This could, for example, be a washing machine or dryer with a flexible start time.
        ///
        /// For more information on the different control types, see [the S2 documentation website](https://docs.s2standard.org/docs/concepts/control-types/).
        pub mod ppbc {
            use crate::common::*;
        }
    );
    let mut ombc: ItemMod = parse_quote!(
        /// Types specific to the Operation Mode Based Control type.
        ///
        /// Use OMBC for devices which can adjust their power producing or consuming behavior, without constraints regarding the duration of the adjustment.
        /// This could, for example, be a power generator.
        ///
        /// For more information on the different control types, see [the S2 documentation website](https://docs.s2standard.org/docs/concepts/control-types/).
        pub mod ombc {
            use crate::common::*;
        }
    );
    let mut frbc: ItemMod = parse_quote!(
        /// Types specific to the Fill Rate Based Control type.
        ///
        /// Use FRBC for devices which can store or buffer energy in some form.
        /// This could, for example, be a smart EV charger, a battery or a fridge/freezer.
        ///
        /// For more information on the different control types, see [the S2 documentation website](https://docs.s2standard.org/docs/concepts/control-types/).
        pub mod frbc {
            use crate::common::*;
        }
    );
    let mut ddbc: ItemMod = parse_quote!(
        /// Types specific to the Demand Driven Based Control type.
        ///
        /// Use DDBC for devices which need to match a given demand of something, but are flexible in what way they satisfy this demand.
        /// This could, for example, be a hybrid heat pump.
        ///
        /// For more information on the different control types, see [the S2 documentation website](https://docs.s2standard.org/docs/concepts/control-types/).
        pub mod ddbc {
            use crate::common::*;
        }
    );
    let mut common: ItemMod = parse_quote!(
        pub mod common {
            //! Types common to all S2 control types.
            //!
            //! This module includes a lot of useful types when working with S2. The most important of these is [`Message`]: this is what you'll be sending and receiving.
            //!
            //! For more information on common S2 concepts, please refer to [the S2 documentation website](https://docs.s2standard.org/docs/welcome/).
            impl Id {
                /// Create a randomly generated `Id`.
                pub fn generate() -> Self {
                    Self(uuid::Uuid::new_v4().to_string())
                }
            }

            impl NumberRange {
                pub fn contains(&self, value: f64) -> bool {
                    self.start_of_range >= value && self.end_of_range < value
                }
            }

            impl<T: Into<f64>> From<std::ops::Range<T>> for NumberRange {
                fn from(val: std::ops::Range<T>) -> NumberRange {
                    NumberRange {
                        start_of_range: val.start.into(),
                        end_of_range: val.end.into(),
                    }
                }
            }

            impl From<NumberRange> for std::ops::Range<f64> {
                fn from(val: NumberRange) -> std::ops::Range<f64> {
                    val.start_of_range..val.end_of_range
                }
            }

            impl From<Duration> for chrono::TimeDelta {
                fn from(val: Duration) -> chrono::TimeDelta {
                    chrono::TimeDelta::milliseconds(val.0 as i64)
                }
            }

            impl From<chrono::TimeDelta> for Duration {
                fn from(val: chrono::TimeDelta) -> Duration {
                    Duration(
                        u64::try_from(val.num_milliseconds()).expect("Can't convert a negative chrono::TimeDelta to a common::Duration"),
                    )
                }
            }
        }
    );

    // Remove the `message_type` field from struct definitions.
    let base_contents = RemoveMessageType::fold_file(&mut RemoveMessageType, base_contents);
    let base_contents = ReplaceGeneratedErrorPath::fold_file(&mut ReplaceGeneratedErrorPath, base_contents);

    // Go over each item (e.g. definition) in the source and determine the correct module to place it in.
    // Controltype-specific types (such as `FrbcActuatorStatus`) go in the module corresponding to that controltype,
    // other types (such as `Commodity`) go in `common`.
    for item in &base_contents.items {
        match item {
            syn::Item::Impl(item_impl) => {
                let impl_type_name = match &*item_impl.self_ty {
                    Type::Path(type_path) => type_path.path.segments.last().unwrap().ident.to_string(),
                    Type::Verbatim(token_stream) => token_stream.to_string(),
                    _ => {
                        root_module.extend(item.into_token_stream());
                        continue;
                    }
                };

                let correct_module = if impl_type_name.starts_with("Pebc") {
                    &mut pebc
                } else if impl_type_name.starts_with("Ppbc") {
                    &mut ppbc
                } else if impl_type_name.starts_with("Ombc") {
                    &mut ombc
                } else if impl_type_name.starts_with("Frbc") {
                    &mut frbc
                } else if impl_type_name.starts_with("Ddbc") {
                    &mut ddbc
                } else {
                    &mut common
                };

                correct_module.content.as_mut().unwrap().1.push(item.clone());
            }

            syn::Item::Enum(item_enum) => {
                let enum_name = item_enum.ident.to_string();
                let correct_module = if enum_name.starts_with("Pebc") {
                    &mut pebc
                } else if enum_name.starts_with("Ppbc") {
                    &mut ppbc
                } else if enum_name.starts_with("Ombc") {
                    &mut ombc
                } else if enum_name.starts_with("Frbc") {
                    &mut frbc
                } else if enum_name.starts_with("Ddbc") {
                    &mut ddbc
                } else {
                    &mut common
                };

                // Special case for `Message`: the generated enum is serde(untagged), but needs to be serde(tag = "message_type")
                // with the variants renamed so it matches the S2 spec.
                if enum_name == "Message" {
                    let mut item_enum = item_enum.clone();
                    // Change `serde(untagged)` to `serde(tag = "message_type)`.
                    for attr in &mut item_enum.attrs {
                        let Meta::List(lst) = &mut attr.meta else { continue };
                        if lst.path.is_ident("serde") {
                            lst.tokens = quote!(tag = "message_type");
                        }
                    }

                    // Add `serde(rename = "FRBC.ActuatorStatus")` to all the variants where that's necessary.
                    for variant in &mut item_enum.variants {
                        let variant_name = variant.ident.to_string();
                        if variant_name.starts_with("Pebc")
                            || variant_name.starts_with("Ppbc")
                            || variant_name.starts_with("Ombc")
                            || variant_name.starts_with("Frbc")
                            || variant_name.starts_with("Ddbc")
                        {
                            let (prefix, name) = variant_name.split_at(4);
                            let prefix = prefix.to_uppercase();
                            let variant_rename = format!("{prefix}.{name}");
                            variant.attrs.push(parse_quote!(#[serde(rename = #variant_rename)]));
                        }
                    }

                    // Add a function to easily extract the message ID.
                    let id_extractors = item_enum.variants.iter().map(|variant| {
                        let ident = variant.ident.clone();
                        if ident != "ReceptionStatus" {
                            Some(quote! { Message::#ident(x) => Some(x.message_id.clone()) })
                        } else {
                            Some(quote! { Message::#ident(_) => None })
                        }
                    });
                    let extractor_impl: Item = parse_quote! {
                        impl Message {
                            pub fn id(&self) -> Option<Id> {
                                match self {
                                    #(#id_extractors),*
                                }
                            }
                        }
                    };

                    correct_module.content.as_mut().unwrap().1.push(syn::Item::Enum(item_enum));
                    correct_module.content.as_mut().unwrap().1.push(extractor_impl);
                } else {
                    correct_module.content.as_mut().unwrap().1.push(item.clone());
                }
            }

            syn::Item::Struct(item_struct) => {
                let struct_name = &item_struct.ident;
                let struct_name_str = struct_name.to_string();
                let correct_module = if struct_name_str.starts_with("Pebc") {
                    &mut pebc
                } else if struct_name_str.starts_with("Ppbc") {
                    &mut ppbc
                } else if struct_name_str.starts_with("Ombc") {
                    &mut ombc
                } else if struct_name_str.starts_with("Frbc") {
                    &mut frbc
                } else if struct_name_str.starts_with("Ddbc") {
                    &mut ddbc
                } else {
                    &mut common
                };

                // For structs, also generate a constructor impl.
                // This is a very basic impl, which might be of limited use.
                match &item_struct.fields {
                    syn::Fields::Named(fields) => {
                        let parameters = fields
                            .named
                            .iter()
                            .filter_map(|field| {
                                let Some(name) = &field.ident else { return None };
                                if name == "message_id" {
                                    return None;
                                };

                                let ty = &field.ty;
                                Some(quote! { #name: #ty })
                            })
                            .collect::<Vec<_>>();
                        let create_constructor = parameters.len() <= 1;

                        if create_constructor {
                            // Create a constructor in cases of 1 or 0 parameters.
                            let field_names = fields.named.iter().filter_map(|field| {
                                let Some(ident) = &field.ident else { return None };
                                if ident == "message_id" {
                                    Some(quote!(message_id: Id::generate()))
                                } else {
                                    Some(quote!(#ident))
                                }
                            });

                            let constructor_impl = parse_quote! {
                                impl #struct_name {
                                    pub fn new(#(#parameters),*) -> #struct_name {
                                        #struct_name {
                                            #(#field_names),*
                                        }
                                    }
                                }
                            };

                            correct_module.content.as_mut().unwrap().1.push(item.clone());
                            correct_module.content.as_mut().unwrap().1.push(constructor_impl);
                        } else {
                            // Derive a builder in cases of 2+ parameters.
                            let mut item_struct = item_struct.clone();
                            item_struct.attrs.push(parse_quote!(#[derive(bon::Builder)]));
                            item_struct.attrs.push(parse_quote!(#[builder(on(::std::string::String, into))]));
                            if let syn::Fields::Named(fields) = &mut item_struct.fields {
                                for field in fields.named.iter_mut() {
                                    let Some(ident) = &field.ident else { continue };
                                    if ident == "message_id" {
                                        // By default, generate message_id
                                        field.attrs.push(parse_quote!(#[builder(default = Id::generate())]));
                                    }
                                }
                            }

                            correct_module.content.as_mut().unwrap().1.push(Item::Struct(item_struct));
                        }
                    }

                    _ => {
                        correct_module.content.as_mut().unwrap().1.push(item.clone());
                    }
                };
            }

            _ => {
                root_module.extend(item.into_token_stream());
            }
        }
    }

    // Replace the type definitions and references to those types.
    pebc = ReplaceTypeDefinitions::fold_item_mod(&mut ReplaceTypeDefinitions, pebc);
    ppbc = ReplaceTypeDefinitions::fold_item_mod(&mut ReplaceTypeDefinitions, ppbc);
    ombc = ReplaceTypeDefinitions::fold_item_mod(&mut ReplaceTypeDefinitions, ombc);
    frbc = ReplaceTypeDefinitions::fold_item_mod(&mut ReplaceTypeDefinitions, frbc);
    ddbc = ReplaceTypeDefinitions::fold_item_mod(&mut ReplaceTypeDefinitions, ddbc);
    common = ReplaceTypeReferences::fold_item_mod(&mut ReplaceTypeReferences, common);

    // Put it all into the top-level module.
    root_module.extend(common.into_token_stream());
    root_module.extend(pebc.into_token_stream());
    root_module.extend(ppbc.into_token_stream());
    root_module.extend(ombc.into_token_stream());
    root_module.extend(frbc.into_token_stream());
    root_module.extend(ddbc.into_token_stream());

    // Write the results to a file.
    let output = prettyplease::unparse(&syn::parse2(root_module).expect("Error parsing the resulting module"));
    let mut out_file = Path::new(&env::var("OUT_DIR").expect("No environment variable OUT_DIR")).to_path_buf();
    out_file.push("generated.rs");
    fs::write(out_file, output).expect("Error writing output to file");
}
