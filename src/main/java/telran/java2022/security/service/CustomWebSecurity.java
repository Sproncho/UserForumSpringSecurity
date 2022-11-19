package telran.java2022.security.service;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.post.model.Post;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

@Service("customSecurity")
@RequiredArgsConstructor
public class CustomWebSecurity {
	
	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;

	public boolean checkPostAuthor(String postId, String userName) {
		Post post = postRepository.findById(postId).orElse(null);
		return post != null && userName.equalsIgnoreCase(post.getAuthor());
	}

	public boolean checkUserPasswordDate(String userName){
		UserAccount userAccount = userAccountRepository.findById(userName).orElse(null);
		return userAccount != null && ChronoUnit.DAYS.between(userAccount.getLastPasswordEdit(), LocalDate.now()) > 60;

	}
}
