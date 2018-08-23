export class StringUtils {
    static compare(ascending: boolean, first: string, second: string): number {
        const lowerLeft = (ascending ? first : second).toLocaleLowerCase();
        const lowerRight = (ascending ? second : first).toLocaleLowerCase();

        if (lowerLeft < lowerRight) {
            return -1;
        } else if (lowerLeft > lowerRight) {
            return 1;
        } else {
            return 0;
        }
    }
}
