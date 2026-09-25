package com.quespot.domain.user.repository;

import com.quespot.domain.user.entity.User;
import com.quespot.domain.user.enums.LoginProvider;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByProviderAndEmail(LoginProvider provider, String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.provider = :provider and u.email = :email")
    Optional<User> findByProviderAndEmailForUpdate(
            @Param("provider") LoginProvider provider,
            @Param("email") String email
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :userId")
    Optional<User> findByIdForUpdate(@Param("userId") Long userId);
}
