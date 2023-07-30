# [HIGH] Insurance Fund#depositFor - Insurance Funds can be manipulated and users can end up with 0 shares and permanent fund loss

## Summary

A malicious user can manipulate the insurance funds so that subsequent users get 0 shares even after transferring funds.

## Vulnerability Detail

The `depositFor()` function in InsuranceFund.sol decides on the number of shares that a depositor should have in the following way:

## Impact

```solidity
if (_pool == 0) {
shares = amount;
} 
else {
shares = amount * _totalSupply / _pool;
}
```

The value of `_pool` is determined by calling the `_totalPoolValue()` function, which iterates across all assets in the insurance fund pool and returns the sum of all assets. The `_totalPoolValue()` function determines the number of tokens of each asset in the following manner:

```solidity
for (uint i; i < assets.length; i++) {
uint _balance = IERC20(address(assets[i].token)).balanceOf(address(this));

if (_balance == 0) continue;
uint numerator = _balance * uint(oracle.getUnderlyingPrice(address(assets[i].token)));
uint denomDecimals = assets[i].decimals;
totalBalance += (numerator / 10 ** denomDecimals);
}
```

This opens up a vulnerability since it uses the `balanceOf()` function that the IERC20 interface provides.

When the first user ever to interact with the insurance fund contract is about to deposit an ERC20 token, the attacker can front-run the transaction and simply transfer a small amount of an asset that the insurance fund supports apart from VUSD. Since `depositFor()` is not called here, shares are not issued, but the `_pool` value will be positive. Therefore, this statement will execute:

```solidity
else {
shares = amount * _totalSupply / _pool;
}
```

Since `_totalSupply` is 0 and `_pool` is non-zero, the innocent user will get 0 shares, and subsequently, all users will start getting 0 shares.

## Code Snippet

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/InsuranceFund.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/InsuranceFund.sol#L89)

```
function depositFor(address to, uint amount) override public { 
```

## Tool used

Manual Review

## Recommendation

It is advised to keep track of assets deposited in the contract state itself so that ERC20 transfers which do not call the `depositFor()` function of the contract cannot manipulate the `_pool` value, or minimum liquidity must be added by the team and it must be added to the contract logic so that the team’s deposit is not front-run.

# [HIGH] InsuranceFund#depositFor - Insurance Fund share mispricing can result in depositors getting 0 shares and attacker stealing all the funds 
## Summary

A malicious user with existing shares can front-run other deposit transactions so that other users get 0 shares, and the attacker can after that steal funds.

## Vulnerability Detail

The `depositFor()` function in `InsuranceFund.sol` decides on the number of shares that a depositor should have in the following way:

```solidity
if (_pool == 0) {

shares = amount;

} else {

shares = amount * _totalSupply / _pool;

}
```

The `_pool` value is determined by calling the `_totalPoolValue()` function, which iterates across all assets in the insurance fund pool and returns the sum of all assets.

Since the initial number of shares is determined by simply equating shares = amount, the attacker can follow these steps to steal user funds:

1. Make a deposit of a small amount, let us say 1 vUSD, by calling the `depositFor()` function. The attacker gets 1 share. Immediately call the unbond function as well.
    
2. Observe multiple subsequent deposit transactions, and let’s say the highest deposit transaction is of value x. However, the sum of values of this set of transactions must exceed x.
    
3. The attacker transfers a vUSD value of `x+1` to the contract without calling the `depositFor()` function. This means that the total supply of shares minted is 1, but the pool value increases by `x+1` vUSD.
    
4. The subsequent transactions, all less than the value of `x+1` vUSD go through, and all of them get 0 shares since `shares = amount * (1 share) / (1+x+1 vUSD)`, and the amount is lesser than `x+2`.
    
5. After the unbonding period, the attacker withdraws a surplus of vUSD.
    

## Impact

A malicious user can front-run the first insurance fund deposit and manipulate the insurance fund contract into issuing 0 shares for subsequent deposits and steal the insurance funds thereafter.

## Code Snippet

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/InsuranceFund.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/InsuranceFund.sol#L89)

```
function depositFor(address to, uint amount) override public { 
```

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/InsuranceFund.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/InsuranceFund.sol#L116)

```
function unbondShares(uint shares) external { 
```

## Tool used

Manual Review

## Recommendation

There are two possible steps:

1. The team must add and burn a minimum liquidity value when deploying the contract and then only open it to the public. This must be set within the contract logic. Thus, such an attack becomes expensive.
    
2. The asset balances can be tracked within the contract state itself so that share mispricing is avoided.


# [HIGH] Compilation error in _debitFrom method due omitted variable name for address parameter
## Summary

Omitting the variable name for the address parameter can lead to compilation errors or unexpected behavior during function calls. Solidity 0.8.0 and later versions require explicit data location for parameters in function calls when the type is not used as an argument. Not providing a variable name for the address parameter violates this requirement and results in a compilation error. By providing a variable name, you ensure compliance with the Solidity syntax and avoid potential errors.

## Vulnerability Detail

POC in Remix testDebitFrom function for the test:

```solidity
pragma solidity ^0.8.9;

contract TestContract {
    uint256 public constant SCALING_FACTOR = 1e12;
    uint256 public circulatingSupply;
    function testDebitFrom() public pure returns (bool) {
        try _debitFrom(0x123, 100) {
            // The function call succeeded, which is unexpected
            return false;
        } catch Error(string memory error) {
            // Verify that the error message is as expected
            return (keccak256(abi.encodePacked(error)) == keccak256(abi.encodePacked("TypeError: Data location must be explicitly given for parameters in function calls where the type is not used as an argument.")));
        } catch {
            // Catch any other exception
            return false;
        }
    }
    
    function _debitFrom(address, uint _amount) internal virtual returns(uint) {
        circulatingSupply -= _amount;
        _amount = _amount / SCALING_FACTOR;
        require(_amount > 1, "HGT: Insufficient amount"); // so that _amount != 0 in the next line
        _amount -= 1; // round down when withdrawing
        return _amount;
    }
}
```

In this test case, the testDebitFrom function attempts to call the \_debitFrom function with an address argument (0x123) but without specifying a variable name for the address parameter. The try-catch block is used to catch any exceptions that occur during the function call.  
If you run this test case, it will return true if the error message matches the expected error, indicating that the lack of a variable name for the address parameter indeed produces an error.  
By running the testDebitFrom function, it will return true if the error message matches the expected error, confirming that the lack of a variable name for the address parameter produces the intended error in Solidity 0.8.9.

## Impact

`_debitFrom` is called in `_send` function and `_send` function is called from`deposit` and `withdraw`.  
It is recommended for this error be fixed in order for the other methods to work properly.

## Code Snippet

[https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/HGT.sol#L24-L30](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/HGT.sol#L24-L30)

```solidity
    function _debitFrom(address, uint _amount) internal virtual override returns(uint) {
        circulatingSupply -= _amount;
        _amount = _amount / SCALING_FACTOR;
        require(_amount > 1, "HGT: Insufficient amount"); // so that _amount != 0 in the next line
        _amount -= 1; // round down when withdrawing
        return _amount;
    }
```

## Tool used

Manual Review, Remix

## Recommendation

Provide variable name `_from` for address parameter.

```diff
-     function _debitFrom(address, uint _amount) internal virtual override returns(uint) {
+     function _debitFrom(address _from, uint _amount) internal virtual override returns(uint) {
```

# [MEDIUM] Oracle#getUnderlyingPrice - ChainLinkAdapterOracle will return the wrong price for asset if underlying aggregator hits minAnswer
## Summary

Chainlink Oracles have a built-in circuit breaker in case prices go outside predetermined minPrice and maxPrice price bands. Therefore, if an asset suffers a huge loss in value, such as the LUNA crash, the chainlink oracle will return the wrong prices, and the protocol can go into debt.

## Vulnerability Detail

The `Oracle.sol` contract uses a chainlink aggregator oracle to get the latest price for setting the index price in the protocol. However, if an asset listed on the exchange suffers a huge change in value, like that of the LUNA crash, the Chainlink oracle will return the wrong prices. The protocol will keep getting the set `minPrice` or `maxPrice` as the answer, while the real price might differ. Since the index price will be set wrong because of this, the funding rates will be wrong and users will suffer losses.

The referred code snippet where prices are fetched is as follows:

```solidity
function getUnderlyingPrice(address underlying)
        virtual
        external
        view
        returns(int256 answer)
    {
        if (stablePrice[underlying] != 0) {
            return stablePrice[underlying];
        }
        (,answer,,,) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();
        require(answer > 0, "Oracle.getUnderlyingPrice.non_positive");
        answer /= 100;
    }
```

## Impact

The Oracle contract does not check if `minPrice` or `maxPrice` circuit breakers are hit by the chainlink aggregator. This might result in a loss for users of the protocol.

## Code Snippet

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/Oracle.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/Oracle.sol#L24)

```
 function getUnderlyingPrice(address underlying) 
```

## Tool used

Manual Review

## Recommendation

Check if minPrice/maxPrice circuit breakers are hit, and apply appropriate procedures if they are hit.

## Reference

Venus on BSC was exploited similarly when LUNA crashed: [https://rekt.news/venus-blizz-rekt/](https://rekt.news/venus-blizz-rekt/).

# [MEDIUM] ClearingHouse#updatePositions - Lack of Enforced Order in Function Calls 
## Summary

The `updatePositions` function must be called every time after `settleFunding` to keep the `lastFundingPaid[trader]` value updated to match `lastFundingTime`. However, the current implementation does not enforce this order, which could lead to a discrepancy between these two values.

## Vulnerability Detail

The `settleFunding` function updates the `lastFundingTime` value, representing the latest time funding was settled. The `updatePositions` function, on the other hand, is supposed to update `lastFundingPaid[trader]` to the `lastFundingTime` for each trader. However, there is no guarantee in the code that `updatePositions` will be called immediately after `settleFunding`. This lack of guaranteed order can lead to a situation where lastFundingTime is more recent than `lastFundingPaid[trader]`.

## Impact

Currently, these specific variables are not used elsewhere in the contract, so the impact of this discrepancy might be minimal. However, it is crucial to consider future updates. If these values are used for any calculations or processes in future versions of the contract, this discrepancy could lead to significant problems, depending on the context.

## Code Snippet

[https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/ClearingHouse.sol#L241C2-L241C2](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/ClearingHouse.sol#L241C2-L241C2)

```solidity
function settleFunding(IAMM _amm) internal {
    ...
    lastFundingTime = _blockTimestamp();
    ...
}

function updatePositions(address trader, Position memory position) internal {
    ...
    if (lastFundingPaid[trader] != lastFundingTime) {
        lastFundingPaid[trader] = lastFundingTime;
    }
    ...
}
```

## Tool used

Manual Review

## Recommendation

Enforce the call to `updatePositions` within the `settleFunding` function for all traders. This enforcement could be done by calling `updatePositions` directly from `settleFunding` or using an event-driven model where an event emitted by `settleFunding` triggers `updatePositions`.

# [MEDIUM] Oracle#getUnderlyingPrice - No stale price checks could lead to price manipulation by the user 
## Summary

The smart contract Oracle.sol does not implement stale price checks by sanitizing the return values potentially leading to outdated and inaccurate oracle data.

## Vulnerability Detail

The `getUnderlyingPrice()` function in the Oracle.sol contract fetches the price of an asset from the Chainlink Oracle but doesn’t check if the price data is stale. This oversight could result in outdated and potentially inaccurate Oracle data if there are problems reaching consensus (e.g., Chainlink nodes abandon the Oracle, chain congestion, vulnerability/attacks on the Chainlink system).

## Impact

Given the current market price, users could exploit this to execute transactions at stale prices, which can be exploited to borrow more assets than they should be able to.

## Code Snippet

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/Oracle.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/Oracle.sol#L24)

```
function getUnderlyingPrice(address underlying) 
```

```solidity
function getUnderlyingPrice(address underlying)
    virtual
    external
    view
    returns(int256 answer)
{
    if (stablePrice[underlying] != 0) {
        return stablePrice[underlying];
    }
    (,answer,,,) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();
    require(answer > 0, "Oracle.getUnderlyingPrice.non_positive");
    answer /= 100;
}
```

## Tool used

Manual Review

## Recommendation

`getUnderlyingPrice()` should be updated to do additional checks to ensure the Oracle prices are not stale. The below variables should be returned and used: `roundId`, `timestamp`, and `answeredInRound`.

```diff
function getUnderlyingPrice(address underlying)
    virtual
    external
    view
    returns(int256 answer)
{
    if (stablePrice[underlying] != 0) {
        return stablePrice[underlying];
    }
- (,answer,,,) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();
+ (uint80 roundId, int256 answer,uint256 timestamp,, uint80 answeredInRound) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();+ require(answeredInRound >= roundId, "Stale price") 
+ require(timestamp != 0, "Round not complete")
   require(answer > 0, "Oracle.getUnderlyingPrice.non_positive");
   answer /= 100;
}
```

# [MEDIUM] ClearingHouse#updatePositions - Unbounded AMM array might cause a denial of service

## Summary

The smart contract ClearingHouse has a function `updatePositions()` which could potentially cause a Denial of Service (DoS) if the `amms` array is unbounded and becomes too large.

## Vulnerability Detail

The `updatePositions()` function iterates over the `amms` array. If this array grows too large, the function could exceed the block gas limit, making it impossible to invoke this function. This scenario would effectively halt the operation of the contract, which could be considered as a Denial of Service (DoS) attack.

## Impact

A successful DoS attack would halt the operations of the contract, making it unusable. This could affect any traders using the contract, and potentially could lead to financial loss or interrupted service.

## Code Snippet

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/ClearingHouse.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/ClearingHouse.sol#L247)

```
 for (uint i; i < numAmms; ++i) { 
```

```solidity
uint numAmms = amms.length;
            for (uint i; i < numAmms; ++i) {
                (int256 _fundingPayment, int256 cumulativePremiumFraction) = amms[i].updatePosition(trader);
                if (_fundingPayment != 0) {
                    fundingPayment += _fundingPayment;
                    emit FundingPaid(trader, i, _fundingPayment, cumulativePremiumFraction);
                }
            }
```

## Tool used

Manual Review

## Recommendation

Consider implementing a mechanism to limit the size of the `amms` array. Alternatively, you could change the implementation to avoid iterating over the entire `amms` array within a single transaction. This could be done by processing a subset of the array at a time or using a pattern such as the 'pull over push' strategy for updating positions.

# [MEDIUM] InsuranceFund#syncDeps - Governance can change vUSD address at any time and deposits can get lost 
## Summary

The smart contract InsuranceFund.sol contains a potentially harmful function, `syncDeps()`, which allows for the contract address of vusd to be changed at any time by the Governance address. In some edge cases, this may cause users' funds to be lost.

## Vulnerability Detail

The `syncDeps()` function can change the contract address of vusd without any restrictions. This change can interfere with the transactions of depositing and withdrawing vusd by users, possibly causing a loss of funds. If a new address is set for vusd between a user's deposit and withdraw transactions, the user could end up withdrawing a different vusd variant, such as VUSDv2, while having initially deposited VUSD.

## Impact

The users' funds are at risk of being lost due to this vulnerability. If the `syncDeps()` function is called and vusd is set to a new address in the middle of deposit and withdraw transactions, users could end up withdrawing nothing, hence suffering a fund loss.

## Code Snippet

[2023-04-hubble-exchange-crimson-rat-reach/hubble-protocol/contracts/InsuranceFund.sol](https://github.com/sherlock-audit/2023-04-hubble-exchange-crimson-rat-reach/blob/cc7eac2fd258da91e315cfa52de98c60b9d43185/hubble-protocol/contracts/InsuranceFund.sol#L321)

```
 function syncDeps(address _registry) public onlyGovernance { 
```

```solidity
function syncDeps(IRegistry _registry) public onlyGovernance {
    vusd = IERC20(_registry.vusd());
    marginAccount = _registry.marginAccount();
}
```

## Tool used

Manual Review

## Recommendation

A recommended solution is to consider making vusd unchangeable. However, if migration of vusd must be considered for future upgrades, you should change the `syncDeps()` function to ensure that the balance after the change is not less than the balance before the change. Here is a recommended change to the function:

```diff
function syncDeps(IRegistry _registry) public onlyGovernance {
+   uint _balance = balance();
    vusd = IERC20(_registry.vusd());
+   require(balance() >= _balance);
    marginAccount = _registry.marginAccount();
}
```

This will ensure that the balance of vusd does not decrease, preventing potential losses to the users' funds.