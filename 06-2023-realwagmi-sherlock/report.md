# [HIGH] Fees accumulated while Multipool tokens are not staked in Dispatcher end up lost

## Summary

Fees accumulated while Multipool tokens are not staked in Dispatcher end up lost

## Vulnerability Detail

Fee growth for tokens deposited in Multipool are tracked for the whole Multipool in vars:  

[2023-06-real-wagmi-crimson-rat-reach/concentrator/contracts/Multipool.sol](https://github.com/sherlock-audit/2023-06-real-wagmi-crimson-rat-reach/blob/a0f47c5b57e8ee9a59835287eff20b8aed63c35b/concentrator/contracts/Multipool.sol#L93)

```
FeeGrowth public feesGrowthInsideLastX128; 
```

However a user (Alice) cannot withdraw her fees if she keeps her Multipool tokens outside of `Dispatcher`.  
When she decides to deposit her Multipool tokens in the dispatcher, her fee index gets tracked, allowing her to claim fees from multipool from that point on:  

[2023-06-real-wagmi-crimson-rat-reach/concentrator/contracts/Dispatcher.sol](https://github.com/sherlock-audit/2023-06-real-wagmi-crimson-rat-reach/blob/a0f47c5b57e8ee9a59835287eff20b8aed63c35b/concentrator/contracts/Dispatcher.sol#L203-L204)

```
 user.feeDebt0 = feesGrow.accPerShare0; 
 user.feeDebt1 = feesGrow.accPerShare1; 
```

But if Alice waits too long before depositing tokens into the Dispatcher, the fees accumulated for her tokens end up lost, and may further break accounting for the `Dispatcher`, as lp tokens withdrawed to service fees are computed using `_totalSupply` for the MultiPool:  

[2023-06-real-wagmi-crimson-rat-reach/concentrator/contracts/Dispatcher.sol](https://github.com/sherlock-audit/2023-06-real-wagmi-crimson-rat-reach/blob/a0f47c5b57e8ee9a59835287eff20b8aed63c35b/concentrator/contracts/Dispatcher.sol#L196)


```
 _withdrawFee(pool, lpAmount, reserve0, reserve1, _totalSupply, deviationBP); 
```

Which means that those fees are not even distributed accross earlier Dispatcher depositors, and are simply lost.

## Impact

Part of Uniswap liquidity gathered fees end up lost for Multipool tokens not deposited into Dispatcher straight away.

## Tool used

Manual Review

## Recommendation

This mechanism needs rethinking, either keeping track of fees accumulated for a user directly in Multipool in the same manner as it is done currently in `Dispatcher`, or an easier solution is to create a periphery which deposits in `Multipool` and restakes in `Dispatcher` in the same transaction

# [HIGH] Multipool deposit is vulnerable to reentrancy attack by which operator can drain liquidity

## Summary

Function deposit() in Multipool.sol is vulnerable to reentrancy by which the operator can mint lp tokens at a cheap price.

## Vulnerability Detail

The function rebalanceAll() makes an ext call to swapTarget after being called by the operator. The operator can set an arbitrary swapTarget to be approved and pass the same to the function.

The external call in question is here:

```
    if (params.amountIn > 0) {
        _approveToken(params.zeroForOne ? token0 : token1, params.swapTarget, params.amountIn);
        (bool success, ) = params.swapTarget.call(params.swapData);
        ErrLib.requirement(success, ErrLib.ErrorCode.ERROR_SWAPPING_TOKENS);
    }
```

While slippage checks prevent the operator from draining funds, it is possible for the swapTarget function to do a large swap, and enable the operator to mint LP tokens at cheap before returning the funds.

This can be done by swapping the tokens, and by having an attacker controlled token in the swap path, do a reentrant call to the deposit() function.  
This way, the operator can use the LP tokens to later drain liquidity from the pool.

## Impact

The operator can set a malicious swapTarget, make a reentrant call to deposit() function and mint LP tokens at a cheap value. The LP tokens can be used for draining liquidity from the pool.

## Code Snippet

[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L857C10-L857C10](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L857C10-L857C10)

```
    if (params.amountIn > 0) {
        _approveToken(params.zeroForOne ? token0 : token1, params.swapTarget, params.amountIn);
        (bool success, ) = params.swapTarget.call(params.swapData);
        ErrLib.requirement(success, ErrLib.ErrorCode.ERROR_SWAPPING_TOKENS);
    }
```

## Recommendation

Set the deposit() function to nonReentrant.

# [HIGH] Deposit transactions lose funds to front-running when multiple fee tiers are available

## Summary

Deposit transactions lose funds to front-running when multiple fee tiers are available

## Vulnerability Detail

The deposit transaction takes in minimum parameters for amount0 and amount1 of tokens that the user wishes to deposit, but no parameter for the minimum number of LP tokens the user expects to receive. A malicious actor can limit the number of LP tokens that the user receives in the following way:

A user Alice submits a transaction to deposit tokens into Multipool where (amount0Desired, amount0Min) > (amount1Desired, amount1Min)

A malicious actor Bob can front-run this transaction if there are multiple feeTiers:

- by first moving the price of feeTier1 to make tokenA very cheap (lots of tokenA in the pool)
- then moving the price of feeTier2 in opposite direction to make tokenB very cheap (lots of tokenB in the pool)

This results in reserves being balanced accross feeTiers, and the amounts resulting from `_optimizeAmounts` are balanced as well:  
[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L780-L808](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L780-L808)

So the minimum amounts checks pass and but results as less LP tokens minted, because even though the reserves are balanced, they are also overinflated due to the large swap, and the ratio:  
[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L468-L470](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L468-L470)

becomes a lot smaller than before the large swap

## Impact

The user loses funds as a result of maximum slippage.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Add extra parameters for the minimum number of LP tokens that the user expects, instead of just checking non-zero amount:  
[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L473](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L473)

# [HIGH] Insufficient lpAmount Validation Could Lead to Stuck Funds During Significant Price Movements

## Summary

The vulnerability is caused by the possibility of the estimated `lpAmount` being greater than or equal to the user's shares due to significant price movements, which could lead to users' funds being stuck and inaccessible.

## Vulnerability Detail

The vulnerability arises when estimating the `lpAmount` using the `_estimateWithdrawalLp` function in both the `withdraw` and `deposit` functions. The calculated `lpAmount` is then used to update the user's shares. However, if a significant price movement occurs, there is no guarantee that the `lpAmount` will always be less than the user's shares.

If the `lpAmount` is greater than or equal to the user's shares, users' funds may become stuck and inaccessible. This issue is especially concerning during extreme market fluctuations when users might need to withdraw their funds urgently.

## Impact

The impact of this vulnerability is high, as it could prevent users from withdrawing or depositing their funds during significant price movements. Moreover, it could lead to a loss of funds for affected users.

## Code Snippet

In the withdraw function:  
[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Dispatcher.sol#L234](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Dispatcher.sol#L234)

```solidity
{
    (uint256 fee0, uint256 fee1) = _calcFees(feesGrow, user);
    lpAmount = _estimateWithdrawalLp(reserve0, reserve1, _totalSupply, fee0, fee1);
}
user.shares -= lpAmount;
```

In the deposit function:  
[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Dispatcher.sol#L193](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Dispatcher.sol#L193)

```solidity
{
    (uint256 fee0, uint256 fee1) = _calcFees(feesGrow, user);
    lpAmount = _estimateWithdrawalLp(reserve0, reserve1, _totalSupply, fee0, fee1);
}
user.shares -= lpAmount;
```

## Tool used

Manual Review

## Recommendation

1. Modify the `_estimateWithdrawalLp` function to account for price movements by adding a `priceFactor` parameter.

```solidity
function _estimateWithdrawalLp(
    uint256 reserve0,
    uint256 reserve1,
    uint256 _totalSupply,
    uint256 amount0,
    uint256 amount1,
    uint256 priceFactor
) private pure returns (uint256 shareAmount) {
    shareAmount =
        ((amount0 * _totalSupply) / (reserve0 * priceFactor) + (amount1 * _totalSupply) / reserve1) /
        2;
}
```

2. Update the `withdraw` and `deposit` functions to include the `priceFactor` when calling `_estimateWithdrawalLp`.

```solidity
// In the withdraw function:
{
    (uint256 fee0, uint256 fee1) = _calcFees(feesGrow, user);
    lpAmount = _estimateWithdrawalLp(reserve0, reserve1, _totalSupply, fee0, fee1, priceFactor);
}

// In the deposit function:
{
    (uint256 fee0, uint256 fee1) = _calcFees(feesGrow, user);
    lpAmount = _estimateWithdrawalLp(reserve0, reserve1, _totalSupply, fee0, fee1, priceFactor);
}
```

3. In both the `withdraw` and `deposit` functions, add a loop to adjust the `priceFactor` until a valid `lpAmount` is found, ensuring that users can withdraw their funds even in cases of extreme market fluctuations.

```solidity
// In the withdraw function:
uint256 priceFactor = 1;
while (lpAmount >= user.shares) {
    priceFactor++;
    (uint256 fee0, uint256 fee1) = _calcFees(feesGrow, user);
    lpAmount = _estimateWithdrawalLp(reserve0, reserve1, _totalSupply, fee0, fee1, priceFactor);
}

// In the deposit function:
uint256 priceFactor = 1;
while (lpAmount >= user.shares) {
    priceFactor++;
    (uint256 fee0, uint256 fee1) = _calcFees(feesGrow, user);
    lpAmount = _estimateWithdrawalLp(reserve0, reserve1, _totalSupply, fee0, fee1, priceFactor);
}
```

this will allow users to withdraw their funds even in cases of extreme market fluctuations.

# [MED] Multipool#MINIMUM_AMOUNT is not suitable for low decimal tokens such as USDC/USDT

## Summary

The constant `MINIMUM_AMOUNT` has been hardcoded to `1_000_000` in the contract. However, this hardcoded value may not be suitable for tokens with low decimal values, such as USDT/USDC, which only have 6 decimals.

## Vulnerability Detail

The hardcoded value of `1_000_000` for `MINIMUM_AMOUNT` assumes that the tokens used in the contract have a higher decimal value. However, when tokens with lower decimal values, such as USDT/USDC (6 decimals), are used, the value of `1_000_000` becomes prohibitively large.

## Impact

The hardcoded `MINIMUM_AMOUNT` could inadvertently prevent certain users from interacting with the contract if they are using low decimal tokens such as USDT/USDC. Since the `MINIMUM_AMOUNT` is set high for these tokens, these users would need a prohibitively large amount of the token to interact with the contract, effectively excluding them from participation.

## Code Snippet

[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L74C6-L74C6](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L74C6-L74C6)

```solidity
uint256 public constant MINIMUM_AMOUNT = 1000_000;

```

## Tool used

Manual Review

## Recommendation

We recommend that the MINIMUM\_AMOUNT not be hardcoded. Instead, it would be better to set the `MINIMUM_AMOUNT` dynamically based on the decimal value of the token used. Alternatively, `MINIMUM_AMOUNT` could be set relative to the token's decimals on a per-token basis. This would make the contract more flexible and adaptable to different tokens, including those with lower decimal values, and ensure all potential users can interact with the contract.

# [MED] Multipool#getAmountOut has a hardcoded feeTier which can cause the function to revert

## Summary

In the Multipool#getAmountOut function, the `feeTier` has been hardcoded as `500`. If a poolAddress for that specific `feeTier` doesn't exist, the whole function will revert.

## Vulnerability Detail

The code in question below has the `feeTier` hardcoded to `500`, which could lead to a scenario where the pool at index 500 does not exist, leading to an attempted read of an empty address. This causes the function to revert. It could also limit the function's usefulness, as it can't interact with other pools in the `underlyingTrustedPools` array.

## Impact

The hardcoding of the `feeTier` limits the flexibility and robustness of the `getAmountOut` function. If the pool at index 500 does not exist or is not the desired pool for interaction, the function will fail or give inappropriate results. This could affect any functionality in the contract that relies on this function.

## Code Snippet

[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L823](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L823)

```
(int56[] memory tickCumulatives, ) = IUniswapV3Pool(underlyingTrustedPools[500].poolAddress).observe(secondsAgo);
```

## Tool used

Manual Review

## Recommendation

We recommend removing the hardcoding of the `feeTier` value. Instead, this value should be passed as a parameter to the getAmountOut function. This would allow the function to interact with any pool in the `underlyingTrustedPools` array, increasing the flexibility of the function and ensuring it won't fail if the pool at index 500 does not exist. It is also important to ensure proper validation of the `feeTier` input to avoid invalid index access.

# [MED] Unsafe type casting of _param in MultiPoll#setParam() leads to Incorrect Address Assignment 

## Summary

In the `setParam()` of the contract, there is a potential casting issue with the `_param` variable. The code attempts to cast \_param to address using the expression

```solidity
operator = address(uint160(_param));
```

However, this casting operation may lead to unexpected behavior or an exception `if _param > uint160.max`

## Vulnerability Detail

The `setParam()` function in the contract contains a vulnerability that can result in an incorrect address assignment. The vulnerability arises when attempting to cast a large value(e.g., `14615016373309029182036848327162830196559325429758`) to `uint160` and subsequently to address. The casting operation assumes that the value of `_param` falls within the valid range for `uint160`, but this assumption is incorrect.

## Impact

As a result, the contract may assign an unintended and potentially invalid address to the operator variable, compromising the functionality and security of the contract.

## Code Snippet

[https://github.com/sherlock-audit/2023-06-real-wagmi-crimson-rat-reach/blob/main/concentrator/contracts/Multipool.sol#L908](https://github.com/sherlock-audit/2023-06-real-wagmi-crimson-rat-reach/blob/main/concentrator/contracts/Multipool.sol#L908)

```solidity
else if (_managing == MANAGING.OPERATOR) {
            ErrLib.requirement(_param != 0, ErrLib.ErrorCode.INVALID_ADDRESS);
            operator = address(uint160(_param));
```

## Tool used

Manual Review

## Recommendation

If the value of `_param` exceeds the maximum allowed for `uint160`, terminate the transaction or implement appropriate error-handling measures to prevent incorrect address assignment or contract termination. Reverting the transaction with a descriptive error message is recommended.

A [SafeCast Library](https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeCast) must be used everywhere a typecast is done or

```solidity
ErrLib.requirement(_param != 0, ErrLib.ErrorCode.INVALID_ADDRESS); 
require(_param <= type(uint160).max, "Value exceeds maximum for uint160"); 
operator = address(uint160(_param));
```

# [MED] Multipool#twapDuration Short TWAP Duration Could be subject to manipulation by a malicious validator (FTM)

## Summary

This vulnerability could expose the contract to price manipulation by a malicious validator, particularly in a Proof-of-Stake (PoS) environment.  
[https://chainsecurity.com/oracle-manipulation-after-merge/](https://chainsecurity.com/oracle-manipulation-after-merge/)

## Vulnerability Detail

The twapDuration in the Multipool.sol contract is set to 150, which is considered too short. Short TWAP durations can allow an attacker who controls the next block to hide information from arbitrageurs, preventing them from rebalancing the market before the manipulation opportunity disappears.

```solidity
uint32 public twapDuration = 150;
```

## Impact

If exploited, this vulnerability could lead to inaccurate price calculations and potentially result in financial losses for users interacting with the contract. Furthermore, in PoS environments, validators could take advantage of Maximum Extractable Value (MEV) opportunities, leading to unfair advantages and undermining the trust in the system.

## Code Snippet

In the Multipool.sol contract, the twapDuration variable is defined as follows:  
[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L88](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L88)

```solidity
uint32 public twapDuration = 150;
```

## Tool used

Manual Review

## Recommendation

consider increasing the twapDuration to make it more difficult for an attacker to manipulate the price. Additionally, ensure that the contract takes MEV into account when designing its mechanisms and assumes competition and equal access to on-chain information for all users.

```solidity
uint32 public twapDuration = 600; // Increase the duration to a more secure value
```

# [MED] Multipool#deposit - Minimum amount checks can be bypassed

## Summary

Function `deposit()` in `Multipool.sol` implements `MINIMUM_AMOUNT` checks for desired amounts, but not for minimum amounts.

## Vulnerability Detail

The function implements `MINIMUM_AMOUNT` checks for desired amounts as shown below:

```solidity
        ErrLib.requirement(
            amount0Desired > MINIMUM_AMOUNT && amount1Desired > MINIMUM_AMOUNT,
            ErrLib.ErrorCode.AMOUNT_TOO_SMALL
        );
```

However, it does not implement the same checks for `amount0Min` and `amount1Min`. Therefore, `function _optimizeAmounts()` can return a value lesser than `MINIMUM_AMOUNT`, and the user can end up supplying liquidity lesser than `MINIMUM_AMOUNT`.

Let’s look at the function `_optimizeAmounts()` :

```solidity
            if (amount1Optimal <= amount1Desired) {
                ErrLib.requirement(
                    amount1Optimal >= amount1Min,
                    ErrLib.ErrorCode.INSUFFICIENT_1_AMOUNT
                );
```

It is checked if `amount1Optimal >= amount1Min`, but since `amount1Min` can be lesser than `MINIMUM_AMOUNT`, `amount1Optimal` can be lesser than `MINIMUM_AMOUNT` as well, since no checks for the same have been done.

The function returns `(amount0, amount1)` as `(amount0Desired, amount1Optimal)` respectively. This means that `amount1Optimal` can be lesser than `MINIMUM_AMOUNT` and `amount0Desired` can be a large value.

## Impact

The user can get a much lower lp share since `MINIMUM_AMOUNT` checks are not done. Additionally, it is possible to fill up one side of the pool with tokens by setting `amount0Min/amount1Min` to a very low amount, let’s say 0.

## Code Snippet

[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L440-L443](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L440-L443)

```solidity
        ErrLib.requirement(
            amount0Desired > MINIMUM_AMOUNT && amount1Desired > MINIMUM_AMOUNT,
            ErrLib.ErrorCode.AMOUNT_TOO_SMALL
        );
```

[https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L793-L796](https://github.com/sherlock-audit/2023-06-real-wagmi/blob/82a234a5c2c1fc1921c63265a9349b71d84675c4/concentrator/contracts/Multipool.sol#L793-L796)

```solidity
            if (amount1Optimal <= amount1Desired) {
                ErrLib.requirement(
                    amount1Optimal >= amount1Min,
                    ErrLib.ErrorCode.INSUFFICIENT_1_AMOUNT
                );
```

## Tool used

Manual Review

## Recommendation

Employ minimum checks for `amount0Min` and `amount1Min` as well in `deposit()` function of `Multipool.sol`.