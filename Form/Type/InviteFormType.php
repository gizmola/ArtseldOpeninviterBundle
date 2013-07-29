<?php

/*
 * This file is part of the Artseld\OpeninviterBundle package.
 *
 * (c) Dmitry Kozlovich <artseld@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Artseld\OpeninviterBundle\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;

class InviteFormType extends AbstractType
{
    protected $contacts;

    public function __construct($contacts = array())
    {
        $this->contacts = $contacts;
    }

    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
           // ->add('message', 'textarea', array(
               // 'required' => true,
               // //'label' => 'artseld_openinviter.label.message',
            	//'label' => 'Message',
           // ))
            ->add('email', 'choice', array(
                'required' => true,
                //'label' => 'artseld_openinviter.label.recipients',
            	'label' => 'Recipients',
                'multiple' => true,
                'expanded' => true,
                'choices' => $this->getRecipientsChoices(),
            ))
        ;
    }

    public function getName()
    {
        return 'artseld_openinviter_invite_form';
    }

    /**
     * @return array
     */
    protected function getRecipientsChoices()
    {
        return array_values($this->contacts);
    }
}
