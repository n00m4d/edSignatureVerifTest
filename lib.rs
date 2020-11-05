#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod edSignatureTest {
    use ed25519_compact::*;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct EdSignatureTest {
        /// Stores a single `bool` value on the storage.
        value: bool,
    }

    impl EdSignatureTest {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(init_value: bool) -> Self {
            Self { value: init_value }
        }

        /// Constructor that initializes the `bool` value to `false`.
        ///
        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new(Default::default())
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        #[ink(message)]
        pub fn flip(&mut self) {
            self.value = !self.value;
        }

        /// Simply returns the current value of our `bool`.
        #[ink(message)]
        pub fn get(&self) -> bool {
            self.value
        }

        #[ink(message)]
        pub fn verification_test(&self) -> bool {
            let pub_k = PublicKey::new([ 127,252,97,23,127,195,92,204,223,99,66,175,180,175,225,189,24,149,89,93,9,97,78,71,35,151,24,222,202,25,77,46 ]);
            let message: [u8;64] = [ 102,97,99,54,51,55,51,51,98,52,50,55,57,99,55,100,100,51,56,53,54,55,102,52,53,54,50,50,99,51,100,102,100,101,56,48,101,98,57,49,56,99,102,48,97,48,55,56,48,54,53,56,100,52,51,56,50,97,100,100,56,50,99,51 ];
            let raw_signature: [u8;64] = [ 232,71,14,96,84,189,182,2,217,205,205,177,213,244,118,238,240,107,247,179,176,40,37,118,210,92,118,153,95,202,254,201,2,51,83,199,48,80,173,83,44,125,155,54,78,120,113,86,119,20,143,219,168,169,69,152,8,229,144,95,105,21,193,10 ];
            let signature = Signature::from_slice(raw_signature.as_ref()).unwrap();
        
            let result: bool = pub_k.verify(message.as_ref(), &signature).is_ok();

            result
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// We test if the default constructor does its job.
        #[test]
        fn default_works() {
            let edSignatureTest = EdSignatureTest::default();
            assert_eq!(edSignatureTest.get(), false);
        }

        /// We test a simple use case of our contract.
        #[test]
        fn it_works() {
            let mut edSignatureTest = EdSignatureTest::new(false);
            assert_eq!(edSignatureTest.get(), false);
            edSignatureTest.flip();
            assert_eq!(edSignatureTest.get(), true);
        }
    }
}
