package com.authserver.entity;

import com.authserver.enums.SocialType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Comment;

import java.time.LocalDateTime;

@Entity
@Table(name = "social"
//        indexes = {@Index(name = "idx_user_id", columnList = "userId")},
//        uniqueConstraints = @UniqueConstraint(name = "unique_user_id", columnNames = {"userId"})
)
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Social {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @Enumerated(EnumType.STRING)
    private SocialType socialType;

    private String socialId;

    private String socialEmail;

    private String accessToken;

    private LocalDateTime connectDate;

}
