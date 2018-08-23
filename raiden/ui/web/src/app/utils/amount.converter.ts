export function amountFromDecimal(amount: number, decimals: number): number {
    return Math.round(amount * (10 ** decimals));
}

export function amountToDecimal(amount: number, decimals: number): number {
    return (amount / (10 ** decimals));
}
