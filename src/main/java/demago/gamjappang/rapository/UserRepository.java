package demago.gamjappang.rapository;

import demago.gamjappang.model.User;

import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository가 없어도 IoC가 됨 <- JpaRepository를 상속했기 떄문에
public interface UserRepository extends JpaRepository<User, Integer> {

    // findBy -> 규칙 Username문법
    // select * from user where username = ?
    public User findByUsername(String username); // JPA Query Methods
}
