package io.webxml.korisnikservice.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.webxml.korisnikservice.model.Korisnik;
import io.webxml.korisnikservice.service.KorisnikService;

@Service
public class UserDetails implements UserDetailsService{
	
	private @Autowired
	KorisnikService korisnikService;
	
	@Override
	public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(String email) throws UsernameNotFoundException{
		//pronadji korisnika po emailu
		Korisnik korisnik = korisnikService.getKorisnikByEmail(email);
		if(korisnik == null) {
			//ako user nije pronadjen cepi ga
			throw new UsernameNotFoundException("User '" + email + "' not found");
		}
		
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		grantedAuthorities.add(new SimpleGrantedAuthority(korisnik.getRola()));
		
		//novi ulogovani korisnik sa svojim autoritetima
		return new org.springframework.security.core.userdetails.User(korisnik.getEmail(), korisnik.getLozinka(),
				true, true, true, true, grantedAuthorities);	
	}
	


}
