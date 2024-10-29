package com.practice.spring_security.domain;

import com.practice.spring_security.enums.Provider;
import com.practice.spring_security.enums.Role;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String nickname;

    @Column(unique = true)
    private String email;

    private String password;

    @Column(name = "img_url")
    private String imageUrl;

    @Column
    @Enumerated(EnumType.STRING)
    private Role role;

    @Column
    @Enumerated(EnumType.STRING)
    private Provider provider;

    @Column(name = "provide_id")
    private String providerId;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RefreshToken> refreshTokens= new ArrayList<>();

    public void setEmail(String email){
        this.email = email;
    }
}

