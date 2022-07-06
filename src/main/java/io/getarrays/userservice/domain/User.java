package io.getarrays.userservice.domain;

import java.util.ArrayList;
import java.util.Collection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username; // john123 or email 도 String 이므로 가능하다
    private String password;

    @ManyToMany(fetch = FetchType.EAGER) // 사용자를 불러올때마다 db 에서 역할을 가지고 올 것이다.
    private Collection<Role> roles = new ArrayList<>();
}
