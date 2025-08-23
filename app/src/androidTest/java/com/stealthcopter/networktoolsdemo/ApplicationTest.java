package com.stealthcotper.networktools;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

import android.app.Application;

@RunWith(AndroidJUnit4.class)
public class ApplicationTest {

    @Test
    public void testApplication() {
        Application application = ApplicationProvider.getApplicationContext();
        assertNotNull(application);
    }
}