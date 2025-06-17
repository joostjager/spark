import { FRAGMENT as StaticDepositQuoteOutputFragment } from "../objects/StaticDepositQuoteOutput.js";

export const GetClaimDepositQuote = `
  query StaticDepositQuote(
    $transaction_id: String!
    $output_index: Int!
    $network: BitcoinNetwork!
  ) {
    static_deposit_quote(
      input: {
        transaction_id: $transaction_id,
        output_index: $output_index,
        network: $network
      }
    ) {
      ...StaticDepositQuoteOutputFragment
    }
  }
  ${StaticDepositQuoteOutputFragment}
`;
