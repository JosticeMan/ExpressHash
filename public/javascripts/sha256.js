/**
 * Reformatted SHA-256 Implementation pulled from given Github Repo
 * Annotated the code to deepen understanding of the SHA-256 algorithm
 *
 * Creating a new implementation of SHA-256 may prove difficult due to differences in the
 * types of streams we target and the assumed stream.
 *
 * @note - This function only supports ASCII! Not unicode text.
 * @source - Pulled from https://github.com/geraintluff/sha256
 * @see - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * @param ascii
 * @return {string}
 * @author - Justin Yau (See notes for what I contributed)
 */
var SHA256 = function sha256(ascii) {

    /**
     * <- @see Section 2.2 ->
     * The rotate right (circular right shift) operation, where x is a w-bit word
     * and n is an integer with 0 <= n < w, is defined by ROTR n
     * (x)=(x >> n) |(x << w - n).
     * @param value - w bit word
     * @param amount - n is an integer
     * @return {number}
     */
    function rightRotate(value, amount) {
        return (value>>>amount) | (value<<(32 - amount));
    }

    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length';
    var i, j;
    var result = '';

    var words = [];
    var asciiBitLength = ascii[lengthProperty]*8;

    /**
     * <- @see Section 4.2.2 ->
     * K-constants array represents the first thirty-two bits of the fractional parts of
     * the cube roots of the first sixty-four prime numbers. In hex, these constant words are (from left
     * to right)
     * <- @see Section 5.3.3 ->
     * For SHA-256, the initial hash value, H(0), shall consist of eight 32-bit words:
     * @type {{}}
     */
    //* Caching results is optional - remove/add slash from front of this line to toggle
    // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
    // (we actually calculate the first 64, but extra values are just ignored)
    var hash = SHA256.h = SHA256.h || [];
    // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
    var k = SHA256.k = SHA256.k || [];
    var primeCounter = k[lengthProperty];
    /*/
    var hash = [], k = [];
    var primeCounter = 0;
    //*/
    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
            k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
        }
    }

    /**
     * <- @see Section 5 ->
     * PREPROCESSING
     * Preprocessing consists of three steps: padding the message, M (Sec. 5.1), parsing the message
     * into message blocks (Sec. 5.2), and setting the initial hash value, H(0) (Sec. 5.3).
     */
    ascii += '\x80'; // Append Ƈ' bit (plus zero padding)
    while (ascii[lengthProperty]%64 - 56) {ascii += '\x00'} // More zero padding
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        if (j>>8) return "NON ASCII INPUT. TRY AGAIN WITH PROPER INPUT."; // ASCII check: only accept characters in range 0-255
        words[i>>2] |= j << ((3 - i)%4)*8;
    }
    words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
    words[words[lengthProperty]] = (asciiBitLength);

    /**
     * <- @see Section 6.2.2 ->
     * HASH COMPUTATION
     * 1st Step: Schedule W
     *          - Message Block/Chunk numbers 0 to 15 remain the same
     *          - Else add the results of
     *              - omega1 operation on (W(i-2))
     *              - W(i-7)
     *              - omega0 operation on (W(i-15))
     *              - W(i-16)
     * 2nd Step: Initialize 8 working variables, a-h, with their previous hash values
     * 3rd Step: @see Top of page 3 for all operations to be calculated
     * 4th Step: Add the working variables to their 8 corresponding H blocks
     *
     * @note - @see Section 5.2.1 for more information about message blocks
     */
    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration

        /** STEP 2 */
        var oldHash = hash;
        // This is now the undefinedworking hash", often labelled as variables a...g
        // (we have to truncate as well, otherwise extra entries at the end accumulate
        hash = hash.slice(0, 8);

        /** Very condensed form of STEP 1 and STEP 3 */
        for (i = 0; i < 64; i++) {
            var i2 = i + j;
            // Expand the message into 64 words
            // Used below if
            var w15 = w[i - 15], w2 = w[i - 2];

            // Iterate
            var a = hash[0], e = hash[4];
            /** STEP 3 T1 FUNCTION */
            var temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                + ((e&hash[5])^((~e)&hash[6])) // ch
                + k[i]
                // Expand the message schedule if needed
                + (w[i] = (i < 16) ? w[i] : (
                        w[i - 16]
                        + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) // s0
                        + w[i - 7]
                        + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)) // s1
                    )|0
                );
            /** STEP 3 T2 FUNCTION */
            // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj

            hash = [(temp1 + temp2)|0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
            hash[4] = (hash[4] + temp1)|0;
        }

        /** STEP 4 */
        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i])|0;
        }
    }

    /**
     * Convert the 8 H blocks into their hex decimal equivalents with the leading 0s and concatenate them.
     */
    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            var b = (hash[i]>>(j*8))&255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
};

/**
 * Exports this package to be used by an expressJS server.
 * @type {{sha256: (function(*): string)}}
 */
module.exports = {
    sha256: SHA256
};