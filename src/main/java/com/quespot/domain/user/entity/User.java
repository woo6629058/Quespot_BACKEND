package com.quespot.domain.user.entity;

import com.quespot.domain.user.enums.LoginProvider;
import com.quespot.domain.user.enums.UserRole;
import com.quespot.domain.user.enums.UserStatus;
import com.quespot.global.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_users_provider_email",
                        columnNames = {"provider", "email"}
                )
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @Column(name = "password", length = 255)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 20)
    private LoginProvider provider;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private UserRole role;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    private User(
            String email,
            String password,
            LoginProvider provider,
            UserRole role,
            UserStatus status
    ) {
        this.email = email;
        this.password = password;
        this.provider = provider;
        this.role = role;
        this.status = status;
    }

    public static User createEmailUser(String email, String encodedPassword) {
        return new User(
                email,
                encodedPassword,
                LoginProvider.EMAIL,
                UserRole.USER,
                UserStatus.ACTIVE
        );
    }

    public static User createSocialUser(String email, LoginProvider provider) {
        return new User(
                email,
                null,
                provider,
                UserRole.USER,
                UserStatus.ACTIVE
        );
    }

    public void withdraw() {
        this.email = "withdrawn_%d@deleted.quespot".formatted(id);
        this.status = UserStatus.WITHDRAWN;
        this.deletedAt = LocalDateTime.now();
    }

}
