package com.example.demosecurityquartz.controller;

public class test {
    //    public static void main(String[] args) throws Exception {
//        // 1. 创建一个JobDetail，把实现了Job接口的类邦定到JobDetail 构建者模式 绑定job withIdentity这里起一个唯一的名字
//        JobDetail jobDetail = JobBuilder.newJob(TestJob.class)
//                .withIdentity("job1") // 唯一标识
//                .build();
//        // 2.创建一个Trigger触发器的实例，定义该job立即执行，并且每2秒执行一次，一直执行 repeatForever重复
//        SimpleTrigger trigger = TriggerBuilder
//                .newTrigger()
//                .withIdentity("trigger1") // 唯一标识
//                .startNow() // 立即生效
//                .withSchedule(SimpleScheduleBuilder.simpleSchedule()
//                        .withIntervalInSeconds(2) // 每2秒执行一次
//                        .repeatForever()) // 一直重复执行
//                .build();
//        // 3.创建schedule调度器并执行   StdSchedulerFactory 工厂模式
//        StdSchedulerFactory factory = new StdSchedulerFactory();
//        // 获取调度器实例
//        Scheduler scheduler = factory.getScheduler();
//        // 开启调度器
//        scheduler.start();
//        // 把SimpleTrigger和JobDetail注册给调度器
//        scheduler.scheduleJob(jobDetail, trigger);
//        // 关闭调度器
//        // scheduler.shutdown();
//    }
}
