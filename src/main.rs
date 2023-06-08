use std::io::{self, Write};
use rug::Integer;
use ring::rand::{SystemRandom, SecureRandom};
use xxcalc::polynomial::Polynomial;

fn generate_range(rng: &dyn SecureRandom, lower_bound: i32, upper_bound: i32) -> f64 {
    let mut buf = [0u8; 4];
    loop {
        rng.fill(&mut buf).unwrap();
        let val = u32::from_le_bytes(buf);
        let random = lower_bound + (i64::from(val) % ((upper_bound - lower_bound + 1) as i64)) as i32;
        if random >= lower_bound && random <= upper_bound {
            return f64::from(random);
        }
    }
}

fn poly_modulo(polynomial: Polynomial, modulus: Polynomial) -> Polynomial {
    polynomial.clone() - ((polynomial / modulus.clone()) * modulus)
}

fn coeff_modulo(coeff_vec: &mut Polynomial, modulus: f64) -> Polynomial {
    for i in 0..coeff_vec.degree() {
        coeff_vec[i] = coeff_vec[i].rem_euclid(modulus);
    }
    coeff_vec.clone()
}

fn generate_keypair() -> ((Polynomial, Polynomial), (((Polynomial, Polynomial), (Polynomial, Polynomial)), (Polynomial, Polynomial))) {
    let rng = SystemRandom::new();

    let mut modulus_coefficients = vec![0.0; 256];
    modulus_coefficients[0] = 1.0;
    modulus_coefficients[255] = 1.0;
    let modulus = Polynomial::new(modulus_coefficients.as_slice());

    let mut s: (Polynomial, Polynomial) = (Polynomial::new(&[1.0; 256]), (Polynomial::new(&[1.0; 256])));
    let mut e: (Polynomial, Polynomial) = (Polynomial::new(&[1.0; 256]), (Polynomial::new(&[1.0; 256])));
    let mut a: ((Polynomial, Polynomial), (Polynomial, Polynomial)) = ((Polynomial::new(&[1.0; 256]), (Polynomial::new(&[1.0; 256]))), 
                                                                       (Polynomial::new(&[1.0; 256]), (Polynomial::new(&[1.0; 256]))));
    for i in 0..256 {
        s.0[i]   = generate_range(&rng, -3, 3);
        s.1[i]   = generate_range(&rng, -3, 3);
        e.0[i]   = generate_range(&rng, -3, 3);
        e.1[i]   = generate_range(&rng, -3, 3);
        a.0.0[i] = generate_range(&rng, -1664, 1664);
        a.0.1[i] = generate_range(&rng, -1664, 1664);
        a.1.0[i] = generate_range(&rng, -1664, 1664);
        a.1.1[i] = generate_range(&rng, -1664, 1664);
    }

    let mut sum_1 = poly_modulo(a.0.0.clone() * s.0.clone(), modulus.clone()) + poly_modulo(a.0.1.clone() * s.1.clone(), modulus.clone());
    let mut sum_2 = poly_modulo(a.1.0.clone() * s.0.clone(), modulus.clone()) + poly_modulo(a.1.1.clone() * s.1.clone(), modulus);

    sum_1 = coeff_modulo(&mut sum_1, 3329.0);
    sum_2 = coeff_modulo(&mut sum_2, 3329.0);

    sum_1 += e.0.clone();
    sum_2 += e.1.clone();

    sum_1 = coeff_modulo(&mut sum_1, 3329.0);
    sum_2 = coeff_modulo(&mut sum_2, 3329.0);

    let t = (sum_1, sum_2);

    (s, (a, t))

}

fn encrypt_plaintext(pk: (((Polynomial, Polynomial), (Polynomial, Polynomial)), (Polynomial, Polynomial)), plaintext: &Integer) -> ((Polynomial, Polynomial), Polynomial) {
    let plaintext = format!("{plaintext:b}");
    let (a, t) = pk;
    let rng = SystemRandom::new();
    let mut modulus_coefficients = vec![0.0; 256];
    modulus_coefficients[0] = 1.0;
    modulus_coefficients[255] = 1.0;
    let modulus = Polynomial::new(modulus_coefficients.as_slice());
    let mut r: (Polynomial, Polynomial) = (Polynomial::new(&[1.0; 256]), (Polynomial::new(&[1.0; 256])));
    let mut e1: (Polynomial, Polynomial) = (Polynomial::new(&[1.0; 256]), (Polynomial::new(&[1.0; 256])));
    let mut e2: Polynomial = Polynomial::new(&[1.0; 256]);
    let mut plaintext_coefficients = Vec::new();


    for i in 0..256 {
        r.0[i]  = generate_range(&rng, -3, 3);
        r.1[i]  = generate_range(&rng, -3, 3);
        e1.0[i] = generate_range(&rng, -2, 2);
        e1.1[i] = generate_range(&rng, -2, 2);
        e2[i]   = generate_range(&rng, -2, 2);
    }

    for character in plaintext.chars() {
        if character == '0' {
            plaintext_coefficients.push(0.0);
        } else {
            plaintext_coefficients.push(1.0);
        }
    }

    plaintext_coefficients.reverse();

    let mut plaintext = Polynomial::new(plaintext_coefficients.as_slice());
    
    plaintext *= Polynomial::constant(1664.0);

    let mut sum_1 = poly_modulo(a.0.0.clone() * r.0.clone(), modulus.clone()) + poly_modulo(a.1.0.clone() * r.1.clone(), modulus.clone());
    let mut sum_2 = poly_modulo(a.0.1.clone() * r.0.clone(), modulus.clone()) + poly_modulo(a.1.1 * r.1.clone(), modulus.clone());

    sum_1 += e1.0.clone();
    sum_2 += e1.1.clone();
    

    sum_1 = coeff_modulo(&mut sum_1, 3329.0);
    sum_2 = coeff_modulo(&mut sum_2, 3329.0);

    let u = (sum_1, sum_2);

    let mut sum = poly_modulo(t.0.clone() * r.0.clone(), modulus.clone()) + poly_modulo(t.1 * r.1.clone(), modulus);

    sum += e2.clone();

    sum += plaintext.clone();

    sum = coeff_modulo(&mut sum, 3329.0);

    let plaintext = Polynomial::new(plaintext_coefficients.as_slice());

    let v = sum.clone() - plaintext;

    (u, v)

}

fn decrypt_ciphertext(ciphertext: ((Polynomial, Polynomial), Polynomial), s: (Polynomial, Polynomial)) -> Integer { 
    let (u, v) = ciphertext;
    let mut plaintext_coefficients = Vec::new();
    let mut modulus_coefficients = vec![0.0; 256];
    modulus_coefficients[0] = 1.0;
    modulus_coefficients[255] = 1.0;
    let modulus = Polynomial::new(modulus_coefficients.as_slice());
    let mut sum = poly_modulo(s.0.clone() * u.0.clone(), modulus.clone()) + poly_modulo(s.1 * u.1, modulus);

    sum = coeff_modulo(&mut sum, 3329.0);

    let mut mn = v - sum.clone();

    mn = coeff_modulo(&mut mn, 3329.0);

    for i in 0..256 {
        if (mn[i] - 1664.0).abs() < mn[i].abs() && (mn[i] - 1664.0).abs() < (mn[i] - 3329.0).abs() {
            plaintext_coefficients.push(1.0);
        } else {
            plaintext_coefficients.push(0.0);
        }
    }

    plaintext_coefficients.reverse();

    let plaintext: String = plaintext_coefficients.iter()
        .map(std::string::ToString::to_string)
        .collect::<String>();

    Integer::from_str_radix(&plaintext, 2).unwrap()

}

fn main() {
    let (sk, pk) = generate_keypair();
    print!("\nEnter the plaintext: ");
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let plaintext = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let ciphertext = encrypt_plaintext(pk, &plaintext);
    println!("\nEncrypted ciphertext: (({}, {}), {})", ciphertext.0.0, ciphertext.0.1, ciphertext.1);
    let output_plaintext = decrypt_ciphertext(ciphertext, sk);
    let output_plaintext = String::from_utf8(hex::decode(format!("{:X}", &output_plaintext)).unwrap()).unwrap();
    println!("\nDecrypted plaintext: {}", output_plaintext.clone());
    assert_eq!(output_plaintext, input, "Correctness not verified.");
    println!("\nCorrectness verified.");
}
