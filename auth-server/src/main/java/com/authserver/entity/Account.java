package com.authserver.entity;

import com.authserver.dto.JoinRequest;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Comment;

@Entity
@Table(name = "account",
        indexes = {@Index(name = "idx_user_id", columnList = "userId")},
        uniqueConstraints = @UniqueConstraint(name = "unique_user_id", columnNames = {"userId"}))
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Comment("user email")
    @Column(nullable = false)
    private String userId;

    private String password;

    @Column(nullable = false)
    private String name;

}
