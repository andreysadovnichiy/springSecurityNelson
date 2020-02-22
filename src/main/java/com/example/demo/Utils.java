package com.example.demo;

import java.util.Calendar;
import java.util.Date;

public class Utils {

    public static Date nowDate() {
        return new Date();
    }

    public static Date addDays(Date date, int days) {
        Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add(Calendar.DATE, days);
        return new Date(c.getTimeInMillis());
    }
}
