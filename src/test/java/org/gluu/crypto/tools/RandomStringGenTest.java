package org.gluu.crypto.tools;

import org.junit.Test;
import org.gluu.crypto.tools.RandomStringGen;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author SMan
 * @version 2022-04-10
 */
public class RandomStringGenTest {

    private static final Logger LOG = LoggerFactory.getLogger(RandomStringGenTest.class);

    private static final int DEF_LENGTH_1 = 16;
    
    private static final int DEF_LENGTH_2 = 21;

    private static final int DEF_NUM_RND_STRINGS = 100;

    @Test
    public void randomStingTest() {
        
        LOG.info("Mode: RandomString.DEF_MODE_ALL");
        checkRandom(DEF_LENGTH_1, 
                RandomStringGen.DEF_MODE_ALL,
                DEF_NUM_RND_STRINGS);
        
        LOG.info("Mode: RandomString.DEF_MODE_ALPHA_LOWER | RandomString.DEF_MODE_ALPHA_UPPER");        
        checkRandom(DEF_LENGTH_1,
                RandomStringGen.DEF_MODE_ALPHA_LOWER | RandomStringGen.DEF_MODE_ALPHA_UPPER,
                DEF_NUM_RND_STRINGS);
        
        LOG.info("Mode: RandomString.DEF_MODE_DIGITS");        
        checkRandom(DEF_LENGTH_1,
                RandomStringGen.DEF_MODE_DIGITS,
                DEF_NUM_RND_STRINGS);
        
        LOG.info("Mode: RandomString.DEF_MODE_SPEC_SYMBOLS");        
        checkRandom(DEF_LENGTH_1,
                RandomStringGen.DEF_MODE_SPEC_SYMBOLS,
                DEF_NUM_RND_STRINGS);
        
        LOG.info("Mode: RandomString.DEF_MODE_ALPHA_LOWER | RandomString.DEF_MODE_ALPHA_UPPER | RandomString.DEF_MODE_DIGITS | RandomString.DEF_MODE_UNDERLINE");        
        checkRandom(DEF_LENGTH_1,
                RandomStringGen.DEF_MODE_ALPHA_LOWER | RandomStringGen.DEF_MODE_ALPHA_UPPER | RandomStringGen.DEF_MODE_DIGITS | RandomStringGen.DEF_MODE_UNDERLINE,
                DEF_NUM_RND_STRINGS);
        
        LOG.info("Mode: RandomString.DEF_MODE_ALPHA_LOWER | RandomString.DEF_MODE_ALPHA_UPPER | RandomString.DEF_MODE_DIGITS | RandomString.DEF_MODE_UNDERLINE");        
        checkRandom(DEF_LENGTH_2,
                RandomStringGen.DEF_MODE_ALPHA_LOWER | RandomStringGen.DEF_MODE_ALPHA_UPPER | RandomStringGen.DEF_MODE_DIGITS | RandomStringGen.DEF_MODE_UNDERLINE,
                DEF_NUM_RND_STRINGS);        
    }

    /**
     * 
     * @param length
     * @param mode
     * @param numSymbols
     */
    private void checkRandom(final int length, final int mode, final int numRndStrings) {
        RandomStringGen randomString_Alpha_UnderLine = new RandomStringGen(length, mode);
        LOG.info("------------------------------------------- >>");
        LOG.info("checkRandom:");
        LOG.info("length = {}", length);        
        LOG.info(String.format("mode = 0X%X", mode));
        LOG.info("numRndStrings = {}", numRndStrings);        
        for (int i = 0; i < numRndStrings; i++) {
            String rndString = randomString_Alpha_UnderLine.nextString();
            LOG.info("i = {}; rndString = {}", i, rndString);
            Assert.assertTrue(rndString.length() == length);
            checkSymbols(rndString, mode);
        }
        LOG.info("------------------------------------------- <<");
    }

    /**
     * 
     * @param message
     * @param mode
     */
    private void checkSymbols(final String message, final int mode) {
        for (int i = 0; i < message.length(); i++) {
            char currSymb = message.charAt(i);
            boolean found = false;
            if ((mode & RandomStringGen.DEF_MODE_ALPHA_LOWER) == RandomStringGen.DEF_MODE_ALPHA_LOWER) {
                if (-1 != RandomStringGen.DEF_SYMBOLS_LOWER.indexOf(currSymb)) {
                    found = true;
                }
            }
            if ((mode & RandomStringGen.DEF_MODE_ALPHA_UPPER) == RandomStringGen.DEF_MODE_ALPHA_UPPER) {
                if (-1 != RandomStringGen.DEF_SYMBOLS_UPPER.indexOf(currSymb)) {
                    found = true;
                }
            }
            if ((mode & RandomStringGen.DEF_MODE_DIGITS) == RandomStringGen.DEF_MODE_DIGITS) {
                if (-1 != RandomStringGen.DEF_SYMBOLS_DIGITS.indexOf(currSymb)) {
                    found = true;
                }
            }
            if ((mode & RandomStringGen.DEF_MODE_UNDERLINE) == RandomStringGen.DEF_MODE_UNDERLINE) {
                if (-1 != RandomStringGen.DEF_SYMBOLS_UNDERLINE.indexOf(currSymb)) {
                    found = true;
                }
            }
            if ((mode & RandomStringGen.DEF_MODE_SPEC_SYMBOLS) == RandomStringGen.DEF_MODE_SPEC_SYMBOLS) {
                if (-1 != RandomStringGen.DEF_SYMBOLS_SPEC.indexOf(currSymb)) {
                    found = true;
                }
            }
            Assert.assertTrue(found);
        }
    }

}
