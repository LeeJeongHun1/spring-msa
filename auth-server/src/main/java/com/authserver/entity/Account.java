package com.authserver.entity;

import com.authserver.dto.JoinRequest;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Comment;

@Entity
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Comment("user email")
    @Column(nullable = false)
    private String userId;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;


    public static Account create(JoinRequest request) {
        return Account.builder()
                .userId(request.getUserId())
                .password(request.getPassword())
                .name(request.getName())
                .build();
    }
}
