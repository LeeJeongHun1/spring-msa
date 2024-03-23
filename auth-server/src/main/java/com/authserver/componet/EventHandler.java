package com.authserver.componet;

import com.authserver.dto.JoinRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Slf4j
@Component
public class EventHandler {

    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void sendEmail(JoinRequest request){
        log.info("send email event start");
        log.info("send email address: {}", request.getUserId());
        log.info("send email event end");
    }
}
