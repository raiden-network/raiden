# Scenario: Token swap
- User Alice wants to exchange N tokens X for M tokens Y with user Charlie
- Alice and Charlie have channels for both tokens with enough capacity

**Solution:**

Two token transfers with same hashlock allow to atomically swap tokens with a
predetermined ration. See and `MakerTokenSwapTask` and `TakerTokenSwapTask` in
the code.
